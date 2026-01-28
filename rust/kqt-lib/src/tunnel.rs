use quinn::{
    Connecting, Endpoint, EndpointConfig, MtuDiscoveryConfig,
    congestion::BbrConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    rustls::{self, version::TLS13},
};
use std::{borrow::Cow, sync::Arc, time::Duration};
use tun_rs::DeviceBuilder;

use crate::{
    config::{Config, ConnectTo, Mode},
    crypto::{LiteCertVerifier, ParsedKeypair, ParsedTrustAnchor},
    packet::{clamp_mss, ip_has_more_frag, ip_is_v4, populate_packet_too_big},
    peers::Mappable,
    *,
};
use crate::{
    packet::{FRONT_BUFFER, frag_if_needed, ip_can_frag, move_frag_headers},
    peers::Peers,
};

const KQT_PROTO_VERSION: &'static [u8] = b"kqt/0.1";
const ETH_HDR_LEN: usize = 14;

impl Mode {
    fn extra_hdr(&self) -> usize {
        match self {
            Mode::L2 => ETH_HDR_LEN,
            Mode::L3 => 0,
        }
    }

    fn eth_extra_hdr(&self) -> Option<usize> {
        match self {
            Mode::L2 => Some(ETH_HDR_LEN),
            Mode::L3 => None,
        }
    }

    fn parse_send_target(&self, data: &[u8]) -> Option<peers::SendTarget> {
        match self {
            Mode::L2 => {
                let mac: [u8; 6] = data.get(0..6)?.try_into().unwrap();
                if mac == [0xff; 6] {
                    Some(peers::SendTarget::Broadcast)
                } else {
                    Some(peers::SendTarget::UnicastMAC(peers::MACAddr(mac)))
                }
            }
            Mode::L3 => {
                // Detect IP version
                if ip_is_v4(data) {
                    let addr: [u8; 4] = data.get(16..20)?.try_into().unwrap();
                    // Check multicast
                    if addr[0] & 0xf0 == 0xe0 {
                        return Some(peers::SendTarget::Broadcast);
                    }
                    Some(peers::SendTarget::UnicastIP(addr.into()))
                } else {
                    let addr: [u8; 16] = data.get(24..40)?.try_into().unwrap();
                    // Check multicast
                    if addr[0] == 0xff {
                        return Some(peers::SendTarget::Broadcast);
                    }
                    Some(peers::SendTarget::UnicastIP(addr.into()))
                }
            }
        }
    }

    fn alpn(&self) -> Vec<u8> {
        let mut v = KQT_PROTO_VERSION.to_vec();
        match self {
            Mode::L2 => v.extend_from_slice(b"/L2"),
            Mode::L3 => v.extend_from_slice(b"/L3"),
        }
        v
    }
}

pub enum IfaceSetup {
    Create(String),
    #[cfg(any(unix))]
    Fd(std::os::fd::RawFd),
}

impl Mode {
    fn to_tun_layer(self) -> tun_rs::Layer {
        match self {
            Mode::L2 => tun_rs::Layer::L2,
            Mode::L3 => tun_rs::Layer::L3,
        }
    }
}

impl Config {
    fn build_device(&self, iface: IfaceSetup) -> anyhow::Result<Arc<tun_rs::AsyncDevice>> {
        let device = match iface {
            IfaceSetup::Create(ref name) => DeviceBuilder::new()
                .name(name)
                .layer(self.mode.to_tun_layer())
                .build_async()?,
            #[cfg(any(unix))]
            IfaceSetup::Fd(fd) => unsafe { tun_rs::AsyncDevice::from_fd(fd)? },
        };

        if let Some(mtu) = self.mtu {
            device.set_mtu(mtu)?;
        }
        for addr in self.address.iter() {
            match addr {
                cidr::IpInet::V4(cidr) => {
                    device.add_address_v4(cidr.address(), cidr.network_length())?
                }
                cidr::IpInet::V6(cidr) => {
                    device.add_address_v6(cidr.address(), cidr.network_length())?
                }
            }
        }
        Ok(Arc::new(device))
    }

    async fn apply_routes(&self, device: Arc<tun_rs::AsyncDevice>) -> anyhow::Result<()> {
        if self.routes.len() > 0 {
            let ifindex = device.if_index()?;
            let handle = net_route::Handle::new()?;
            for route in self.routes.iter() {
                let mut r = net_route::Route::new(route.to.address(), route.to.network_length())
                    .with_gateway(route.via)
                    .with_ifindex(ifindex);

                if let Some(metric) = route.metric {
                    #[cfg(any(target_os = "windows", target_os = "linux"))]
                    {
                        r = r.with_metric(metric);
                    }
                    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
                    {
                        tracing::warn!("Route metric is not supported on this OS, ignoring.");
                    }
                }

                handle.add(&r).await?;
                tracing::info!("Added route: {} via {}", route.to, route.via);
            }
        }
        Ok(())
    }
}

pub async fn run(iface: IfaceSetup, cfg: crate::config::Config) -> anyhow::Result<!> {
    // Create Trust Ancrhos & verifier
    let trusts = cfg
        .anchor
        .iter()
        .map(|t| ParsedTrustAnchor::try_from(t.as_str()).map(|e| e.0));
    let verifier = LiteCertVerifier::try_new(cfg.suffix.clone(), trusts)?;
    let verifier = Arc::new(verifier);
    let kp = ParsedKeypair::try_from(cfg.keypair.as_str())?;

    let mut transport = quinn::TransportConfig::default();
    let mut mtu_discovery = MtuDiscoveryConfig::default();
    mtu_discovery
        .interval(Duration::from_secs(30))
        .black_hole_cooldown(Duration::from_secs(10))
        .minimum_change(10);
    transport.mtu_discovery_config(Some(mtu_discovery));
    transport.initial_mtu(cfg.advanced.initial_outer_mtu);
    transport.max_idle_timeout(Some(
        Duration::from_secs(cfg.advanced.max_idle_timeout as u64).try_into()?,
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(cfg.advanced.keepalive as u64)));
    transport.congestion_controller_factory(Arc::new(BbrConfig::default()));
    if let Some(s) = cfg.advanced.send_buffer {
        transport.datagram_send_buffer_size(s);
    }
    if let Some(s) = cfg.advanced.recv_buffer {
        transport.datagram_receive_buffer_size(Some(s));
    }
    let transport = Arc::new(transport);

    let (server_cfg, udp_sock) = if let Some(listen) = cfg.listen {
        let (cert, key) = kp.clone().try_into_rustls(&cfg.suffix)?;
        let mut server_crypto = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS13])
            .with_client_cert_verifier(verifier.clone())
            .with_single_cert(vec![cert], key)?;
        server_crypto.alpn_protocols = vec![cfg.mode.alpn()];
        let mut server_cfg =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
        server_cfg.transport_config(transport.clone());

        let udp_sock = std::net::UdpSocket::bind(listen)?;
        (Some(server_cfg), udp_sock)
    } else {
        let udp_sock = std::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0))?;
        (None, udp_sock)
    };

    let mut endpoint_cfg = EndpointConfig::new(Arc::new(kp.to_hmac_key()));
    let cloned_kp = kp.clone();
    endpoint_cfg.cid_generator(move || Box::new(cloned_kp.to_cid_generator()));
    let mut endpoint = quinn::Endpoint::new(
        endpoint_cfg,
        server_cfg,
        udp_sock,
        quinn::default_runtime().expect("No built-in runtime for quinn"),
    )?;

    let (cert, sk) = kp.try_into_rustls(&cfg.suffix)?;

    let mut client_crypto = rustls::ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![cert], sk)?;
    client_crypto.enable_sni = false; // Disable SNI
    client_crypto.alpn_protocols = vec![KQT_PROTO_VERSION.to_vec()];
    let client_crypto: Arc<rustls::ClientConfig> = Arc::new(client_crypto);
    let mut client_cfg: quinn::ClientConfig =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    client_cfg.transport_config(transport);
    endpoint.set_default_client_config(client_cfg);

    tracing::debug!("Endpoints created");

    let device = cfg.build_device(iface)?;
    tracing::debug!("Device created");
    cfg.apply_routes(device.clone()).await?;

    let store = Peers::new();

    // Handle client
    for conn_cfg in cfg.connect_to {
        tokio::spawn(handle_target(
            endpoint.clone(),
            device.clone(),
            conn_cfg,
            store.clone(),
            cfg.mode,
        ));
    }

    // Handle server
    if cfg.listen.is_some() {
        tokio::spawn(handle_server(
            endpoint,
            device.clone(),
            store.clone(),
            cfg.mode,
        ));
    }

    // Main loop
    let mut buf = Vec::new();
    'pkt: loop {
        let mtu = device.mtu()?;
        buf.resize(mtu as usize + ETH_HDR_LEN + FRONT_BUFFER, 0);
        let buf_start = buf.as_ptr();
        let len: usize = device.recv(&mut buf[FRONT_BUFFER..]).await?;

        let Some(target) = cfg
            .mode
            .parse_send_target(&buf[FRONT_BUFFER..FRONT_BUFFER + len])
        else {
            tracing::debug!("Unable to parse route target, dropping packet");
            continue 'pkt;
        };

        let mut active = &mut buf[FRONT_BUFFER..FRONT_BUFFER + len];
        let mut frag = None;
        let orig_frag = ip_has_more_frag(&active[cfg.mode.extra_hdr()..]);

        #[allow(unused)]
        'frag: loop {
            let active_len = active.len();
            // Don't frag on first try.
            let sending = if let Some(frag) = frag {
                frag_if_needed(frag, active, orig_frag, cfg.mode.extra_hdr())?
            } else {
                &active[..]
            };
            let sending_len = sending.len();
            assert!(active_len >= sending_len);
            let sent = store.send(&target, sending).await;

            let Err(e) = sent else {
                // Sent successfully, check if more frags are present
                if active_len == sending_len {
                    break;
                }

                active = move_frag_headers(sending_len, active, cfg.mode.extra_hdr());
                continue;
            };

            tracing::warn!("Error sending datagram: {:?}", e);
            // Check error, and if applicable, frag
            if let peers::SendError::PacketTooBig { mtu } = e {
                if mtu >= sending_len {
                    // Retry
                    // TODO: bound retry iterations?
                    continue;
                }

                if ip_can_frag(&sending[cfg.mode.extra_hdr()..]) {
                    frag = Some(mtu);
                    continue;
                }

                tracing::debug!("Generating packet too big");
                let pkt_start = sending.as_ptr() as usize - buf_start as usize;
                let pkt_len = sending_len;
                if let Some(pkt) = populate_packet_too_big(
                    mtu - cfg.mode.extra_hdr(),
                    &mut buf,
                    pkt_start,
                    pkt_len,
                    cfg.mode.eth_extra_hdr(),
                )? {
                    device.send(pkt).await?;
                }

                break;
            }

            tracing::error!("Error sending datagram: {:?}", e);
            break;
        }
    }
}

async fn handle_target(
    ep: Endpoint,
    device: Arc<tun_rs::AsyncDevice>,
    cfg: ConnectTo,
    store: Peers,
    mode: Mode,
) -> ! {
    loop {
        let Err(err): anyhow::Result<!> = try {
            // We don't actually use server_name. Use a dummy IPv4 here.
            let conn = ep.connect(cfg.endpoint, "0.0.0.0").map_err(Into::into)?;
            handle_connection(conn, device.clone(), Some(&cfg), store.clone(), mode).await?
        };
        tracing::error!("Outgoing connection to {} closed: {}", cfg.endpoint, err);
        match err.downcast::<quinn::ConnectionError>() {
            Ok(quinn::ConnectionError::TimedOut) => {
                // Immediately retry on timeout
                tracing::info!("Timed out, retrying");
                continue;
            }
            Ok(quinn::ConnectionError::Reset) => {
                // Server restart, immediately retry
                tracing::info!("Server reset, retrying");
                continue;
            }
            _ => {}
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

async fn handle_connection(
    conn: Connecting,
    device: Arc<tun_rs::AsyncDevice>,
    cfg: Option<&ConnectTo>,
    store: Peers,
    mode: Mode,
) -> anyhow::Result<!> {
    let conn = conn.await?;
    let mds = conn.max_datagram_size();
    let addr = conn.remote_address();
    tracing::info!("New connection from {}, max dgram size {:?}", addr, mds);
    store.attach_conn(conn.clone()).await;

    if let Some(cfg) = cfg {
        // Register designated IPs
        for range in cfg.designated_range.iter() {
            store.map(Mappable::IpInet(*range), &conn).await;
        }
    }

    let ret: anyhow::Result<!> = try {
        loop {
            let dgram = conn.read_datagram().await.map_err(Into::into)?;
            tracing::debug!("[RECV] {}", dgram.len());
            if dgram.len() == 0 {
                tracing::warn!("Empty datagram received");
                continue;
            }

            // Clamp MSS
            let patched = if let Some(mds) = conn.max_datagram_size() {
                clamp_mss(dgram.as_ref(), mds, mode.extra_hdr())
            } else {
                Cow::Borrowed(dgram.as_ref())
            };

            // Simply forward to device
            let written = device.send(patched.as_ref()).await.map_err(Into::into)?;
            if written != dgram.len() {
                tracing::warn!(
                    "Partial write to tap device, {} instead of {}",
                    written,
                    dgram.len()
                );
            }

            // TODO: unwrap envelope

            // Also, parse the source MAC address
            if mode == Mode::L2 {
                if let Some(mac) = dgram.get(6..12).and_then(|s| s.try_into().ok()) {
                    let mac = peers::MACAddr(mac);
                    // Register the connection with the MAC address
                    store.map(Mappable::MAC(mac), &conn).await;
                }
            }
        }
    };
    store.detach_conn(&conn).await;
    ret
}

async fn handle_server(
    ep: Endpoint,
    device: Arc<tun_rs::AsyncDevice>,
    store: Peers,
    mode: Mode,
) -> anyhow::Result<()> {
    tracing::info!("Listening on {}", ep.local_addr()?);
    while let Some(incoming) = ep.accept().await {
        let conn = incoming.accept()?;
        let from = conn.remote_address();
        let device_clone = device.clone();
        let store_clone = store.clone();
        tokio::spawn(async move {
            let Err(e) = handle_connection(conn, device_clone, None, store_clone, mode).await;
            tracing::error!("Incoming connection from {} closed: {}", from, e);
        });
    }
    Ok(())
}

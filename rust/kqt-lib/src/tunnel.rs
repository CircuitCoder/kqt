use quinn::{
    Connecting, Endpoint, EndpointConfig, MtuDiscoveryConfig,
    congestion::BbrConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    rustls::{self, version::TLS13},
};
use std::{sync::Arc, time::Duration};

use crate::packet::FRONT_BUFFER;
use crate::{
    backend::{SendError, engine::Engine},
    config::{Config, ConnectTo, Mode},
    crypto::{LiteCertVerifier, ParsedKeypair, ParsedTrustAnchor},
    packet::{ETH_HDR_LEN, populate_packet_too_big},
};

const KQT_PROTO_VERSION: &'static [u8] = b"kqt/0.1";

impl Mode {
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
    #[cfg(any(
        target_os = "windows",
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
    ))]
    Create(String),
    #[cfg(any(unix))]
    Fd { fd: std::os::fd::RawFd, mtu: u16 },
}

#[cfg(any(
    target_os = "windows",
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
impl Mode {
    fn to_tun_layer(self) -> tun_rs::Layer {
        match self {
            Mode::L2 => tun_rs::Layer::L2,
            Mode::L3 => tun_rs::Layer::L3,
        }
    }
}

impl Config {
    fn build_device(&self, iface: &IfaceSetup) -> anyhow::Result<Arc<tun_rs::AsyncDevice>> {
        let device = match iface {
            #[cfg(any(
                target_os = "windows",
                all(target_os = "linux", not(target_env = "ohos")),
                target_os = "macos",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
            ))]
            IfaceSetup::Create(name) => tun_rs::DeviceBuilder::new()
                .name(name)
                .layer(self.mode.to_tun_layer())
                .build_async()?,
            #[cfg(any(unix))]
            IfaceSetup::Fd { fd, .. } => unsafe { tun_rs::AsyncDevice::borrow_raw(*fd)? },
        };

        #[cfg(not(target_os = "android"))]
        {
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
        }
        Ok(Arc::new(device))
    }

    #[cfg(not(feature = "route"))]
    async fn apply_routes(&self, _device: Arc<tun_rs::AsyncDevice>) -> anyhow::Result<()> {
        if self.route.len() > 0 {
            tracing::warn!("Route feature not enabled, ignoring configured routes.");
        }
        Ok(())
    }

    #[cfg(feature = "route")]
    async fn apply_routes(&self, device: Arc<tun_rs::AsyncDevice>) -> anyhow::Result<()> {
        if self.route.len() > 0 {
            let ifindex = device.if_index()?;
            let handle = net_route::Handle::new()?;
            for route in self.route.iter() {
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

    #[cfg(not(target_os = "windows"))]
    fn apply_dns(&self, _device: &tun_rs::AsyncDevice) -> anyhow::Result<()> {
        if self.dns.len() > 0 {
            tracing::warn!("DNS configuration is only supported on Windows, ignoring.");
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn apply_dns(&self, device: &tun_rs::AsyncDevice) -> anyhow::Result<()> {
        device.set_dns_servers(self.dns.as_slice())?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct CancellationToken(tokio_util::sync::CancellationToken);
impl CancellationToken {
    pub fn new() -> Self {
        Self(tokio_util::sync::CancellationToken::new())
    }

    pub fn cancel(&self) {
        self.0.cancel();
    }

    pub fn spawn<R: Send + Sync + 'static>(
        &self,
        fut: impl std::future::Future<Output = R> + Send + 'static,
    ) -> tokio::task::JoinHandle<Option<R>> {
        let child_token = self.0.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = child_token.cancelled() => None,
                r = fut => Some(r),
            }
        })
    }
}

pub async fn run(
    iface: IfaceSetup,
    cfg: crate::config::Config,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
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
    client_crypto.alpn_protocols = vec![cfg.mode.alpn()];
    let client_crypto: Arc<rustls::ClientConfig> = Arc::new(client_crypto);
    let mut client_cfg: quinn::ClientConfig =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    client_cfg.transport_config(transport);
    endpoint.set_default_client_config(client_cfg);

    tracing::debug!("Endpoints created");

    let device = cfg.build_device(&iface)?;
    tracing::debug!("Device created");

    if cfg.table {
        cfg.apply_routes(device.clone()).await?;
    }

    cfg.apply_dns(&*device)?;

    let engine = Engine::new(&cfg, device.clone());

    // Handle client
    for conn_cfg in cfg.connect_to {
        cancel.spawn(handle_client(endpoint.clone(), conn_cfg, engine.clone()));
    }

    // Handle server
    if cfg.listen.is_some() {
        cancel.spawn(handle_server(endpoint, engine.clone(), cancel.clone()));
    }

    let ret = cancel
        .spawn(main_loop(device, engine, cfg.mode, iface))
        .await?;

    // Main loop dies, tear down everything
    cancel.cancel();
    if let Some(e) = ret {
        // If the main loop voluntarily shuts down
        match e {
            Ok(o) => match o {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

async fn main_loop(
    device: Arc<tun_rs::AsyncDevice>,
    engine: Engine,
    mode: Mode,
    _iface: IfaceSetup,
) -> anyhow::Result<!> {
    // Main loop
    let mut buf = Vec::new();
    loop {
        let mtu;
        #[cfg(not(target_os = "android"))]
        {
            mtu = device.mtu()?;
        }
        #[cfg(target_os = "android")]
        {
            let IfaceSetup::Fd {
                mtu: ref init_mtu, ..
            } = _iface;
            mtu = *init_mtu;
        }
        buf.resize(mtu as usize + ETH_HDR_LEN + FRONT_BUFFER, 0);
        let len: usize = device.recv(&mut buf[FRONT_BUFFER..]).await?;

        let Err(e) = engine
            .send_frag(&mut buf[FRONT_BUFFER..FRONT_BUFFER + len])
            .await
        else {
            continue;
        };

        tracing::error!("Error sending datagram: {:?}", e);

        if let SendError::PacketTooBig { mtu } = e {
            tracing::debug!("Generating packet too big");
            if let Some(pkt) = populate_packet_too_big(
                mtu - mode.eth_hdr().unwrap_or(0),
                &mut buf,
                FRONT_BUFFER,
                len,
                mode.eth_hdr(),
            )? {
                device.send(pkt).await?;
            }
        }
    }
}

async fn handle_client(ep: Endpoint, cfg: ConnectTo, engine: Engine) -> ! {
    async fn handle_client_once(
        ep: &Endpoint,
        cfg: &ConnectTo,
        engine: &Engine,
    ) -> anyhow::Result<!> {
        // We don't actually use server_name. Use a dummy IPv4 here.
        let conn = ep.connect(cfg.endpoint, "0.0.0.0")?.await?;
        engine.handle(conn).await
    }

    loop {
        let Err(err) = handle_client_once(&ep, &cfg, &engine).await;
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

async fn handle_server(
    ep: Endpoint,
    engine: Engine,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    async fn handle_server_once(conn: Connecting, engine: Engine) -> anyhow::Result<!> {
        let conn = conn.await?;
        engine.handle(conn).await?;
    }

    tracing::info!("Listening on {}", ep.local_addr()?);
    while let Some(incoming) = ep.accept().await {
        let conn = incoming.accept()?;
        let engine = engine.clone();
        cancel.spawn(async move {
            let from = conn.remote_address();
            let Err(e) = handle_server_once(conn, engine).await;
            tracing::error!("Incoming connection from {} closed: {}", from, e);
        });
    }
    Ok(())
}

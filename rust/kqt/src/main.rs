#![feature(never_type, try_blocks)]

use clap::Parser;
use quinn::{
    Connecting, Endpoint, EndpointConfig, MtuDiscoveryConfig, congestion::BbrConfig, crypto::rustls::{QuicClientConfig, QuicServerConfig}, rustls::{self, version::TLS13}
};
use tun_rs::DeviceBuilder;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use kqt::{cert::{LiteCertVerifier, ParsedKeypair, ParsedTrustAnchor}, packet::populate_packet_too_big, *};
use kqt::peers::Peers;

const KQT_PROTO_VERSION: &'static [u8] = b"kqt/0.1";
const ETH_HDR_LEN: usize = 14;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the config file
    config: PathBuf,

    #[arg(default_value = "kqt0")]
    /// Name of the iface
    name: String,

    #[arg(long, default_value = "1452")]
    /// Initial outer connection MTU
    initial_outer_mtu: u16,

    #[arg(long, default_value = "25")]
    /// Keepalive interval in seconds
    keepalive: u16,

    #[arg(long, default_value = "60")]
    /// Idle timeout in seconds
    max_idle_timeout: u16,

    #[arg(long)]
    /// Override send buffer size
    send_buffer: Option<usize>,

    #[arg(long)]
    /// Overrride recv buffer size
    recv_buffer: Option<usize>,
}

#[tokio::main]
async fn main() -> anyhow::Result<!> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let s = std::fs::read_to_string(&args.config)?;
    let cfg: config::Config = toml::de::from_str(&s)?;

    if cfg.connect_to.is_empty() && cfg.listen.is_none() {
        tracing::error!("At least one of listen or connect_to must be specified.");
        std::process::exit(1);
    }

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
    transport.initial_mtu(args.initial_outer_mtu);
    transport.max_idle_timeout(Some(
        Duration::from_secs(args.max_idle_timeout as u64).try_into()?,
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(args.keepalive as u64)));
    transport.congestion_controller_factory(Arc::new(BbrConfig::default()));
    if let Some(s) = args.send_buffer {
        transport.datagram_send_buffer_size(s);
    }
    if let Some(s) = args.recv_buffer {
        transport.datagram_receive_buffer_size(Some(s));
    }
    let transport = Arc::new(transport);

    let (server_cfg, udp_sock) = if let Some(listen) = cfg.listen {
        let (cert, key) = kp.clone().try_into_rustls(&cfg.suffix)?;
        let mut server_crypto = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS13])
            .with_client_cert_verifier(verifier.clone())
            .with_single_cert(vec![cert], key)?;
        server_crypto.alpn_protocols = vec![KQT_PROTO_VERSION.to_vec()];
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
    endpoint_cfg.cid_generator(move || {
        Box::new(cloned_kp.to_cid_generator())
    });
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

    let device = Arc::new(
        DeviceBuilder::new()
            .name(&args.name)
            .layer(tun_rs::Layer::L2)
            .build_async()?
    );
    if let Some(mtu) = cfg.mtu {
        device.set_mtu(mtu)?;
    }
    for addr in cfg.address {
        match addr {
            cidr::IpInet::V4(cidr) => device.add_address_v4(
                cidr.address(),
                cidr.network_length()
            )?,
            cidr::IpInet::V6(cidr) => device.add_address_v6(
                cidr.address(),
                cidr.network_length(),
            )?,
        }
    }
    let store = Peers::new();

    tracing::debug!("Device created");

    // Main loop
    // Handle client
    for conn_cfg in cfg.connect_to {
        tokio::spawn(handle_target(
            endpoint.clone(),
            device.clone(),
            conn_cfg.endpoint,
            store.clone(),
        ));
    }
    // Handle server
    if cfg.listen.is_some() {
        tokio::spawn(handle_server(endpoint, device.clone(), store.clone()));
    }
    // Handle tap send
    let mut buf = Vec::new();
    loop {
        let mtu = device.mtu()?;
        buf.resize(mtu as usize + 18, 0);
        let len: usize = device.recv(&mut buf).await?;
        loop {
            if let Err(e) = store.send(&buf[..len]).await {
                match e {
                    peers::SendError::PacketTooBig { mtu } => {
                        if mtu >= len {
                            // Retry
                            // TODO: bound retry iterations?
                            continue;
                        } else {
                            tracing::debug!("Handling Packet Too Big");
                            let ip_pkt = &buf[ETH_HDR_LEN..]; // Skip Ethernet header
                            let mut resp_buf = vec![0u8; 1500 + ETH_HDR_LEN];
                            if let Some(len) = populate_packet_too_big(mtu - ETH_HDR_LEN, ip_pkt, &mut resp_buf[ETH_HDR_LEN..])? {
                                resp_buf[0..6].copy_from_slice(&buf[6..12]);
                                resp_buf[6..12].fill(0);
                                resp_buf[13..14].copy_from_slice(&buf[13..14]);
                                device.send(&resp_buf[..len + ETH_HDR_LEN]).await?;
                            }
                        }
                    }
                    e => {
                        tracing::error!("Error sending datagram: {:?}", e);
                    }
                }
            }
            break;
        }
    }
}

async fn handle_target(
    ep: Endpoint,
    device: Arc<tun_rs::AsyncDevice>,
    addr: SocketAddr,
    store: Peers,
) -> ! {
    loop {
        let Err(err): anyhow::Result<!> = try {
            // We don't actually use server_name. Use a dummy IPv4 here.
            let conn = ep.connect(addr, "0.0.0.0")?;
            handle_connection(conn, device.clone(), store.clone()).await?
        };
        tracing::error!("Outgoing connection to {} closed: {}", addr, err);
        if let Ok(quinn::ConnectionError::TimedOut) = err.downcast::<quinn::ConnectionError>() {
            // Immediately retry on timeout
            tracing::info!("Timed out, retrying");
            continue;
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

async fn handle_connection(
    conn: Connecting,
    device: Arc<tun_rs::AsyncDevice>,
    store: Peers,
) -> anyhow::Result<!> {
    let conn = conn.await?;
    let mds = conn.max_datagram_size();
    let addr = conn.remote_address();
    tracing::info!("New connection from {}, max dgram size {:?}", addr, mds);
    let id = store.register(conn.clone()).await;

    let ret = try {
        loop {
            let dgram = conn.read_datagram().await?;
            tracing::debug!("[RECV] {}", dgram.len());
            if dgram.len() == 0 {
                tracing::warn!("Empty datagram received");
                continue;
            }
            // Simply forward to tap
            let written = device.send(dgram.as_ref()).await?;
            if written != dgram.len() {
                tracing::warn!(
                    "Partial write to tap device, {} instead of {}",
                    written,
                    dgram.len()
                );
            }

            // Also, parse the source MAC address
            if let Some(mac) = dgram.get(7..12).and_then(|s| s.try_into().ok()) {
                let mac_addr = peers::MACAddr(mac);
                // Register the connection with the MAC address
                store.link(id, conn.clone(), mac_addr).await;
            }
        }
    };
    store.unregister(id).await;
    ret
}

async fn handle_server(
    ep: Endpoint,
    device: Arc<tun_rs::AsyncDevice>,
    store: Peers,
) -> anyhow::Result<()> {
    tracing::info!("Listening on {}", ep.local_addr()?);
    while let Some(incoming) = ep.accept().await {
        let conn = incoming.accept()?;
        let from = conn.remote_address();
        let device_clone = device.clone();
        let store_clone = store.clone();
        tokio::spawn(async move {
            let Err(e) = handle_connection(conn, device_clone, store_clone).await;
            tracing::error!("Incoming connection from {} closed: {}", from, e);
        });
    }
    Ok(())
}

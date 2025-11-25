#![feature(never_type, try_blocks)]

mod cert;
mod config;
mod store;

use clap::Parser;
use quinn::{
    Connecting, Endpoint,
    congestion::BbrConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    rustls::{self, version::TLS13},
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use crate::{cert::LiteCertVerifier, store::Store};

const KQT_PROTO_VERSION: &'static [u8] = b"kqt/0.1";

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the config file
    config: PathBuf,

    #[arg(default_value = "kqt0")]
    /// Name of the iface
    name: String,

    #[arg(long, default_value = "1200")]
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
        .map(|t| cert::ParsedTrustAnchor::try_from(t.as_str()).map(|e| e.0));
    let verifier = cert::LiteCertVerifier::try_new(cfg.suffix.clone(), trusts)?;
    let verifier = Arc::new(verifier);
    let kp = cert::ParsedKeypair::try_from(cfg.keypair.as_str())?;

    let mut transport = quinn::TransportConfig::default();
    // TODO: discovery config
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

    let mut endpoint = if let Some(listen) = cfg.listen {
        create_server_endpoint(
            listen,
            verifier.clone(),
            kp.clone(),
            &cfg.suffix,
            transport.clone(),
        )?
    } else {
        quinn::Endpoint::client((std::net::Ipv6Addr::UNSPECIFIED, 0).into())?
    };

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
        tokio_tun::TunBuilder::new()
            .name(&args.name)
            .tap()
            .up()
            .build()?
            .pop()
            .unwrap(),
    );
    let store = Store::new();

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
        if mtu > 65536 {
            tracing::error!(
                "MTU is too large: {}. Maximum supported MTU is 65536 bytes.",
                mtu
            );
            std::process::exit(1);
        }
        buf.resize(mtu as usize + 18, 0);
        let len = device.recv(&mut buf).await?;
        store.send(&buf[..len]).await;
    }
}

fn create_server_endpoint(
    listen: SocketAddr,
    verifier: Arc<LiteCertVerifier>,
    kp: cert::ParsedKeypair,
    suffix: &str,
    transport: Arc<quinn::TransportConfig>,
) -> anyhow::Result<Endpoint> {
    let (cert, key) = kp.try_into_rustls(suffix)?;
    let mut server_crypto = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert], key)?;
    server_crypto.alpn_protocols = vec![KQT_PROTO_VERSION.to_vec()];
    let mut server_cfg =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    server_cfg.transport_config(transport);
    let ep = quinn::Endpoint::server(server_cfg, listen)?;
    Ok(ep)
}

async fn handle_target(
    ep: Endpoint,
    device: Arc<tokio_tun::Tun>,
    addr: SocketAddr,
    store: Store,
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
    device: Arc<tokio_tun::Tun>,
    store: Store,
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
                let mac_addr = store::MACAddr(mac);
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
    device: Arc<tokio_tun::Tun>,
    store: Store,
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

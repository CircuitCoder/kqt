#![feature(never_type, try_blocks)]

mod store;

use clap::Parser;
use quinn::{
    crypto::rustls::{QuicClientConfig, QuicServerConfig}, rustls::{
        self, pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer}, version::TLS13, RootCertStore
    }, Connecting, Endpoint
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use crate::store::Store;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Enable server mode
    #[arg(short, long)]
    listen: Option<SocketAddr>,

    #[arg(short, long, default_value = "/etc/kqt/key.pem")]
    /// Private key for this node
    key: PathBuf,

    #[arg(short, long, default_value = "/etc/kqt/cert.pem")]
    /// Cerfificate for this node
    cert: PathBuf,

    #[arg(long, default_value = "/etc/kqt/ca.pem")]
    /// CA for authenticating incoming connections
    ca: PathBuf,

    #[arg(short, long, default_value = "kqt0")]
    /// Name of the iface
    name: String,

    #[arg(long, default_value = "1460")]
    /// Initial outer connection MTU
    intial_outer_mtu: u16,

    #[arg(long, default_value = "25")]
    /// Keepalive interval in seconds
    keepalive: u16,

    #[arg(long, default_value = "60")]
    /// Idle timeout in seconds
    max_idle_timeout: u16,

    /// Connect to a remote node
    connect: Vec<SocketAddr>,
}

#[tokio::main]
async fn main() -> anyhow::Result<!> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    if args.connect.is_empty() && args.listen.is_none() {
        tracing::error!("At least one of --listen or --connect must be specified.");
        std::process::exit(1);
    }

    // Parse certificate
    let pk = PrivateKeyDer::from_pem_file(&args.key)?;
    let chain = CertificateDer::pem_file_iter(&args.cert)?.collect::<Result<Vec<_>, _>>()?;
    let ca = CertificateDer::pem_file_iter(&args.ca)?.collect::<Result<Vec<_>, _>>()?;

    // Create CA stores
    let mut root_store = rustls::RootCertStore::empty();
    let (ca_added, ca_ignored) = root_store.add_parsable_certificates(ca);
    if ca_added == 0 {
        tracing::error!("No valid certificates found in {}", args.ca.display());
        std::process::exit(1);
    } else {
        tracing::info!("{} CA cert added, {} ignored", ca_added, ca_ignored);
    }
    let root_store = Arc::new(root_store);

    let mut transport = quinn::TransportConfig::default();
    transport.initial_mtu(args.intial_outer_mtu);
    transport.max_idle_timeout(Some(Duration::from_secs(args.max_idle_timeout as u64).try_into()?));
    transport.keep_alive_interval(Some(Duration::from_secs(args.keepalive as u64)));
    let transport = Arc::new(transport);

    let mut endpoint = if let Some(listen) = args.listen {
        create_server_endpoint(listen, root_store.clone(), chain.clone(), pk.clone_key(), transport.clone())?
    } else {
        quinn::Endpoint::client((std::net::Ipv6Addr::UNSPECIFIED, 0).into())?
    };

    let mut client_crypto = rustls::ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .with_root_certificates(root_store.clone())
        .with_client_auth_cert(chain.clone(), pk.clone_key())?;
    client_crypto.alpn_protocols = vec![b"kqt/0.1".to_vec()];
    let client_crypto = Arc::new(client_crypto);
    let mut client_cfg: quinn::ClientConfig = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    client_cfg.transport_config(transport);
    endpoint.set_default_client_config(client_cfg);

    tracing::debug!("Endpoints created");

    let device = Arc::new(tokio_tun::TunBuilder::new()
        .name(&args.name)
        .tap()
        .up().build()?.pop().unwrap());
    let store = Store::new();

    tracing::debug!("Device created");

    // Main loop
    // Handle client
    for addr in args.connect {
        tokio::spawn(handle_target(
            endpoint.clone(),
            device.clone(),
            addr,
            store.clone(),
        ));
    }
    // Handle server
    if args.listen.is_some() {
        tokio::spawn(handle_server(endpoint, device.clone(), store.clone()));
    }
    // Handle tap send
    let mut buf = Vec::new();
    loop {
        let mtu = device.mtu()?;
        if mtu > 65536 {
            tracing::error!("MTU is too large: {}. Maximum supported MTU is 65536 bytes.", mtu);
            std::process::exit(1);
        }
        buf.resize(mtu as usize, 0);
        let len = device.recv(&mut buf).await?;
        store.send(&buf[..len]).await;
    }
}

fn create_server_endpoint(
    listen: SocketAddr,
    root_cert_store: Arc<RootCertStore>,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    transport: Arc<quinn::TransportConfig>,
) -> anyhow::Result<Endpoint> {
    let client_cert_verifier =
        rustls::server::WebPkiClientVerifier::builder(root_cert_store).build()?;
    let mut server_crypto = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS13])
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(chain, key)?;
    server_crypto.alpn_protocols = vec![b"kqt/0.1".to_vec()];
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
            // TODO: explicitly specify subject name
            let conn = ep.connect(addr, "kqt")?;
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
            tracing::debug!("[RECV] {:?}", dgram.as_ref());
            if dgram.len() == 0 {
                tracing::warn!("Empty datagram received");
                continue;
            }
            // Simply forward to tap
            let written = device.send(dgram.as_ref()).await?;
            if written != dgram.len() {
                tracing::warn!("Partial write to tap device, {} instead of {}", written, dgram.len());
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

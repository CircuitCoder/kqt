use clap::Parser;
use quinn::{
    Endpoint,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    rustls::{
        self, RootCertStore,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
        version::TLS13,
    },
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};

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

    /// Connect to a remote node
    connect: Vec<SocketAddr>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.connect.is_empty() && args.listen.is_none() {
        eprintln!("At least one of --listen or --connect must be specified.");
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
        eprintln!("No valid certificates found in {}", args.ca.display());
        std::process::exit(1);
    } else {
        println!("{} CA cert added, {} ignored", ca_added, ca_ignored);
    }
    let root_store = Arc::new(root_store);

    let mut endpoint = if let Some(listen) = args.listen {
        create_server_endpoint(listen, root_store.clone(), chain.clone(), pk.clone_key())?
    } else {
        quinn::Endpoint::client((std::net::Ipv6Addr::UNSPECIFIED, 0).into())?
    };

    let mut client_crypto = rustls::ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .with_root_certificates(root_store.clone())
        .with_client_auth_cert(chain.clone(), pk.clone_key())?;
    client_crypto.alpn_protocols = vec![b"kqt/0.1".to_vec()];
    let client_crypto = Arc::new(client_crypto);
    let client_cfg = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    endpoint.set_default_client_config(client_cfg);

    Ok(())
}

fn create_server_endpoint(
    listen: SocketAddr,
    root_cert_store: Arc<RootCertStore>,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> anyhow::Result<Endpoint> {
    let client_cert_verifier =
        rustls::server::WebPkiClientVerifier::builder(root_cert_store).build()?;
    let server_crypto = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS13])
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(chain, key)?;
    let server_cfg =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    let ep = quinn::Endpoint::server(server_cfg, listen)?;
    Ok(ep)
}

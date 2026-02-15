use std::{borrow::Cow, sync::Arc};

use crate::{backend::{SendError, neighboor::Neighboors, resolver::Resolver, router::Router}, config::Mode, packet::{ETH_HDR_LEN, clamp_mss}};

use ed25519_dalek::VerifyingKey;
use quinn::Connection;
use tokio::sync::RwLock;
use x509_cert::der::Decode;

fn get_remote_identity(conn: &Connection) -> VerifyingKey {
    let certs = conn.peer_identity().expect("Peer identity missing");
    let certs: Box<Vec<quinn::rustls::pki_types::CertificateDer>> =
        certs.downcast().expect("Invalid peer identity");
    assert!(certs.len() == 1);
    let cert = x509_cert::certificate::Certificate::from_der(&certs[0].as_ref())
        .expect("Invalid DER certificate");
    cert.tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .and_then(|bytes| ed25519_dalek::VerifyingKey::try_from(bytes).ok())
        .expect("Invalid public key in certificate")
}

impl Mode {
    pub fn extra_hdr(&self) -> usize {
        match self {
            Mode::L2 => ETH_HDR_LEN,
            Mode::L3 => 0,
        }
    }

    pub fn eth_extra_hdr(&self) -> Option<usize> {
        match self {
            Mode::L2 => Some(ETH_HDR_LEN),
            Mode::L3 => None,
        }
    }
}

#[derive(Clone)]
pub struct Engine {
    resolver: Resolver,
    router: Router,
    neighboors: Arc<RwLock<Neighboors>>,
    dev: Arc<tun_rs::AsyncDevice>,
    mode: Mode,
}

impl Engine {
    pub fn new(mode: Mode, dev: Arc<tun_rs::AsyncDevice>) -> Self {
        // TODO: spawn L3 announcer
        let neighboors = Arc::new(RwLock::new(Neighboors::new()));
        Self {
            resolver: Resolver::new(mode),
            router: Router::new(neighboors.clone()),
            neighboors: neighboors,
            dev,
            mode,
        }
    }

    pub async fn send(&self, pkt: &[u8]) -> Result<(), SendError> {
        use crate::backend::resolver::ResolveResult::*;
        let lookup = &self.resolver.lookup(pkt).await;
        match lookup {
            Unicast(target) => {
                return self.router.send(*target, pkt).await;
            }
            Broadcast => {
                return self.router.broadcast(pkt).await;
            }
            Unreachable => {
                return Err(SendError::Unreachable);
            }
            MalformedPkt => {
                return Err(SendError::MalformedPkt);
            }
        }
    }

    pub async fn handle(&self, conn: quinn::Connection) -> anyhow::Result<!> {
        let identity = get_remote_identity(&conn);

        let mut neighboors = self.neighboors.write().await;
        neighboors.find_neighboor(&identity).attach(conn.clone());
        drop(neighboors);

        let err = self.handle_conn(conn.clone(), identity.clone()).await;

        let mut neighboors = self.neighboors.write().await;
        neighboors.find_neighboor(&identity).detach(&conn);
        err
    }

    async fn handle_conn(
        &self,
        conn: Connection,
        identity: VerifyingKey,
    ) -> anyhow::Result<!> {
        let mds = conn.max_datagram_size();
        let addr = conn.remote_address();
        tracing::info!("New connection from {}, max dgram size {:?}", addr, mds);

        loop {
            let dgram = conn.read_datagram().await?;
            tracing::debug!("[RECV] {}", dgram.len());
            if dgram.len() == 0 {
                tracing::warn!("Empty datagram received");
                continue;
            }

            // Resolver update
            self.resolver.ingress(&identity, dgram.as_ref()).await;

            // Clamp MSS
            let patched = if let Some(mds) = conn.max_datagram_size() {
                clamp_mss(dgram.as_ref(), mds, self.mode.extra_hdr())
            } else {
                Cow::Borrowed(dgram.as_ref())
            };

            // Simply forward to device
            let written = self.dev.send(patched.as_ref()).await?;
            if written != dgram.len() {
                tracing::warn!(
                    "Partial write to tap device, {} instead of {}",
                    written,
                    dgram.len()
                );
            }

            // TODO: unwrap envelope
        }
    }
}
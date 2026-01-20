use ed25519_dalek::VerifyingKey;
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use tokio::sync::RwLock;

use quinn::{Connection, SendDatagramError, VarInt};
use x509_cert::der::Decode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MACAddr(pub [u8; 6]);

#[derive(Error, Debug)]
pub enum SendError {
    #[error("packet too big, mtu: {mtu}")]
    PacketTooBig { mtu: usize },
    #[error("datagram disabled")]
    DgramDisabled,
    #[error("no live connection")]
    NoLiveConnection,
    #[error("unknown error")]
    Unknown(#[from] SendDatagramError),
}

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

struct Remote {
    identity: VerifyingKey,
    outgoing: Option<Connection>,
    incoming: Option<Connection>,
}

impl Remote {
    pub fn send(&self, data: &[u8]) -> Result<(), SendError> {
        // Prefers incoming connection to mimics HTTP/3 traffic
        let conn = self
            .incoming
            .as_ref()
            .or(self.outgoing.as_ref())
            .ok_or(SendError::NoLiveConnection)?;

        let cur_max_dgram_size = conn.max_datagram_size();
        if cur_max_dgram_size.is_none() {
            return Err(SendError::DgramDisabled);
        }

        let cur_max_dgram_size = cur_max_dgram_size.unwrap();

        if let Err(e) = conn.send_datagram(data.to_owned().into()) {
            tracing::debug!("[SEND {}] Failed: {}", conn.remote_address(), e);

            match e {
                quinn::SendDatagramError::TooLarge => Err(SendError::PacketTooBig {
                    mtu: cur_max_dgram_size,
                }),
                e => Err(e.into()),
            }
        } else {
            Ok(())
        }
    }

    pub fn attach(&mut self, conn: Connection) {
        let slot = match conn.side() {
            quinn::Side::Client => &mut self.outgoing,
            quinn::Side::Server => &mut self.incoming,
        };

        // TODO: allow multiple connections?
        if let Some(existing) = slot.replace(conn) {
            existing.close(VarInt::from_u32(0), b"Replaced by new connection");
        }
    }

    pub fn detach(&mut self, conn: &Connection) {
        if conn.side().is_client()
            && Some(conn.stable_id()) == self.outgoing.as_ref().map(|c| c.stable_id())
        {
            self.outgoing = None;
        }

        if conn.side().is_server()
            && Some(conn.stable_id()) == self.incoming.as_ref().map(|c| c.stable_id())
        {
            self.incoming = None;
        }
    }

    pub fn is_live(&self) -> bool {
        self.incoming.is_some() || self.outgoing.is_some()
    }
}

impl std::fmt::Display for Remote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ", hex::encode(&self.identity.as_bytes()[..4]))?;

        let mut delim = "(";
        if let Some(conn) = &self.incoming {
            write!(f, "{}I/{}", delim, conn.remote_address())?;
            delim = ", ";
        }
        if let Some(conn) = &self.outgoing {
            write!(f, "{}O/{}", delim, conn.remote_address())?;
        }
        if delim != "(" {
            write!(f, ")")?;
        }
        Ok(())
    }
}

struct PeersInner {
    // TODO: remote pubkey -> connection mapping
    remotes: Vec<Remote>,
    linked: HashMap<MACAddr, usize>,
}

#[derive(Clone)]
pub struct Peers(Arc<RwLock<PeersInner>>);

impl Peers {
    pub fn new() -> Self {
        let inner = PeersInner {
            remotes: Vec::new(),
            linked: HashMap::new(),
        };
        Peers(Arc::new(RwLock::new(inner)))
    }

    pub async fn register(&self, conn: Connection) {
        let identity = get_remote_identity(&conn);
        let mut inner = self.0.write().await;
        let remote = if let Some(remote) = inner.remotes.iter_mut().find(|r| r.identity == identity)
        {
            remote
        } else {
            inner.remotes.push(Remote {
                identity: identity.clone(),
                outgoing: None,
                incoming: None,
            });
            inner.remotes.last_mut().unwrap()
        };

        remote.attach(conn);
    }

    pub async fn unregister(&self, conn: &Connection) {
        // Don't close it ourself, close it outside
        let identity = get_remote_identity(conn);
        let mut inner = self.0.write().await;
        let Some((idx, remote)) = inner
            .remotes
            .iter_mut()
            .enumerate()
            .find(|(_, r)| r.identity == identity)
        else {
            return;
        };

        remote.detach(&conn);

        if !remote.is_live() {
            inner.linked.retain(|_, &mut v| v != idx);
        }
    }

    pub async fn link(&self, mac: MACAddr, conn: &Connection) {
        let inner = self.0.read().await;
        // Avoid costly locking if already linked
        if inner.linked.contains_key(&mac) {
            return;
        }

        let identity = get_remote_identity(conn);
        let (idx, r) = inner
            .remotes
            .iter()
            .enumerate()
            .find(|(_, r)| r.identity == identity)
            .expect("Connection not registered");

        tracing::debug!("Linking MAC {} to remote {}", hex::encode(mac.0), r,);

        drop(inner);

        let mut inner = self.0.write().await;
        inner.linked.insert(mac, idx);
    }

    pub async fn send(&self, data: &[u8]) -> Result<(), SendError> {
        // Ignore failed connections
        let inner = self.0.read().await;
        let specific = data
            .get(0..6)
            .and_then(|s| inner.linked.get(&MACAddr(s.try_into().unwrap())));
        if let Some(remote_id) = specific {
            let remote = inner
                .remotes
                .get(*remote_id)
                .expect("Inconsistent remote ID");
            tracing::debug!("[SEND {}] {}", remote, data.len());
            remote.send(data)
        } else {
            tracing::debug!("[BROADCAST] {}", data.len());
            for remote in inner.remotes.iter() {
                if remote.is_live() {
                    // FIXME: collect data
                    let _ = remote.send(data);
                }
            }
            Ok(())
        }
    }
}

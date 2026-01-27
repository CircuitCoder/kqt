use cidr::{IpInet, Ipv4Inet, Ipv6Inet};
use ed25519_dalek::VerifyingKey;
use std::{
    collections::BTreeMap,
    hash::Hash,
    net::IpAddr,
    sync::Arc,
};
use thiserror::Error;
use tokio::sync::RwLock;

use quinn::{Connection, SendDatagramError, VarInt};
use x509_cert::der::Decode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MACAddr(pub [u8; 6]);

#[derive(Error, Debug)]
pub enum SendError {
    #[error("packet too big, mtu: {mtu}")]
    PacketTooBig { mtu: usize },
    #[error("datagram disabled")]
    DgramDisabled,
    #[error("no live connection")]
    NoLiveConnection,
    #[error("destination unreachable")]
    Unreachable,
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

struct Neighboor {
    identity: VerifyingKey,
    outgoing: Option<Connection>,
    incoming: Option<Connection>,
}

impl Neighboor {
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

impl std::fmt::Display for Neighboor {
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mappable {
    MAC(MACAddr),
    IpInet(IpInet),
    // FIXME: add node id
}

enum Router {
    DirectOnly,
}

struct PeersInner {
    neighboors: Vec<Neighboor>,
    // TODO: seqno
    mappings: BTreeMap<Mappable, VerifyingKey>,
    router: Router,
}

#[derive(Clone)]
pub struct Peers(Arc<RwLock<PeersInner>>);

#[derive(Debug)]
pub enum SendTarget {
    UnicastMAC(MACAddr),
    UnicastIP(IpAddr),
    Broadcast,
}

const fn const_unwrap<T, E>(r: Result<T, E>) -> T {
    match r {
        Ok(v) => v,
        Err(_e) => panic!("Const unwrap failed"),
    }
}
const MINIMAL_IPV4_INET: Ipv4Inet = const_unwrap(Ipv4Inet::new(std::net::Ipv4Addr::from([0; 4]), 0));
const MINIMAL_IPV6_INET: Ipv6Inet = const_unwrap(Ipv6Inet::new(std::net::Ipv6Addr::from([0; 16]), 0));

enum LookupResult<'k> {
    Broadcast,
    Unicast(&'k VerifyingKey),
    Unreachable,
}

impl<'k> From<Option<&'k VerifyingKey>> for LookupResult<'k> {
    fn from(v: Option<&'k VerifyingKey>) -> Self {
        match v {
            Some(k) => LookupResult::Unicast(k),
            None => LookupResult::Unreachable,
        }
    }
}

impl PeersInner {
    // Lookup the corresponding end receiving node
    fn lookup(&self, t: &SendTarget) -> LookupResult<'_> {
        tracing::debug!("Lookup target: {:?}", t);
        match t {
            SendTarget::UnicastMAC(mac) => if let Some(r) = self.mappings.get(&Mappable::MAC(*mac)) {
                LookupResult::Unicast(r)
            } else {
                // Broadcast on MAC
                LookupResult::Broadcast
            }
            SendTarget::UnicastIP(ip) => {
                let mut lookup = None;
                match ip {
                    IpAddr::V4(v4) => {
                        let mut route = self.mappings.upper_bound(std::ops::Bound::Excluded(
                            &Mappable::IpInet(MINIMAL_IPV4_INET.into())
                        ));
                        while let Some((&Mappable::IpInet(IpInet::V4(r)), t)) = route.next() {
                            if r.contains(&v4) {
                                lookup = Some(t);
                            }
                        }
                    }
                    IpAddr::V6(v6) => {
                        let mut route = self.mappings.upper_bound(std::ops::Bound::Excluded(
                            &Mappable::IpInet(MINIMAL_IPV6_INET.into())
                        ));
                        while let Some((&Mappable::IpInet(IpInet::V6(r)), t)) = route.next() {
                            if r.contains(&v6) {
                                lookup = Some(t);
                            }
                        }
                    }
                }
                lookup.into()
            }
            SendTarget::Broadcast => LookupResult::Broadcast,
        }
    }

    fn route(&self, to: &VerifyingKey) -> Option<&Neighboor> {
        match &self.router {
            Router::DirectOnly => self.neighboors.iter().find(|r| &r.identity == to)
        }
    }
}

// FIXME: check if many-to-one is working
impl Peers {
    pub fn new() -> Self {
        let inner = PeersInner {
            neighboors: Vec::new(),
            mappings: BTreeMap::new(),
            router: Router::DirectOnly,
        };
        Peers(Arc::new(RwLock::new(inner)))
    }

    pub async fn attach_conn(&self, conn: Connection) {
        let identity = get_remote_identity(&conn);
        let mut inner = self.0.write().await;
        let remote =
            if let Some(remote) = inner.neighboors.iter_mut().find(|r| r.identity == identity) {
                remote
            } else {
                inner.neighboors.push(Neighboor {
                    identity: identity.clone(),
                    outgoing: None,
                    incoming: None,
                });
                inner.neighboors.last_mut().unwrap()
            };

        remote.attach(conn);
    }

    pub async fn detach_conn(&self, conn: &Connection) {
        // Don't close it ourself, close it outside
        let identity = get_remote_identity(conn);
        let mut inner = self.0.write().await;
        let Some(remote) = inner
            .neighboors
            .iter_mut()
            .find(|r| r.identity == identity)
        else {
            return;
        };

        remote.detach(&conn);
    }

    pub async fn map(&self, r: Mappable, conn: &Connection) {
        let identity = get_remote_identity(conn);

        let inner = self.0.read().await;
        // Avoid costly locking if already linked
        if inner.mappings.get(&r) == Some(&identity) {
            return;
        }

        tracing::debug!("Linking {:?} to remote {}", r, hex::encode(identity.as_bytes()));

        drop(inner);

        let mut inner = self.0.write().await;
        inner.mappings.insert(r, identity);
    }

    pub async fn send(&self, target: &SendTarget, data: &[u8]) -> Result<(), SendError> {
        // Ignore failed connections
        let inner = self.0.read().await;
        let lookup = inner.lookup(target);
        match lookup {
            LookupResult::Unicast(v) => {
                let remote = inner.route(v).ok_or(SendError::Unreachable)?;
                tracing::debug!("[U {}] {}", remote, data.len());
                remote.send(data)
            }
            LookupResult::Broadcast => {
                tracing::debug!("[B] {}", data.len());
                // Fixme: broadcast to non-adjacent nodes
                for remote in inner.neighboors.iter() {
                    if remote.is_live() {
                        // FIXME: collect error
                        let _ = remote.send(data);
                    }
                }
                Ok(())
            }
            LookupResult::Unreachable => Err(SendError::Unreachable),
        }
    }
}

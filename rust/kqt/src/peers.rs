use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use tokio::sync::RwLock;

use quinn::{Connection, SendDatagramError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MACAddr(pub [u8; 6]);

struct PeersInner {
    linked: HashMap<MACAddr, (usize, Connection)>,
    id: HashMap<usize, Connection>,
    counter: usize,
}

#[derive(Clone)]
pub struct Peers(Arc<RwLock<PeersInner>>);

#[derive(Error, Debug)]
pub enum SendError {
    #[error("packet too big, mtu: {mtu}")]
    PacketTooBig{ mtu: usize },
    #[error("datagram disabled")]
    DgramDisabled,
    #[error("unknown error")]
    Unknown(#[from] SendDatagramError)
}

impl Peers {
    pub fn new() -> Self {
        let inner = PeersInner {
            linked: HashMap::new(),
            id: HashMap::new(),
            counter: 0,
        };
        Peers(Arc::new(RwLock::new(inner)))
    }

    pub async fn register(&self, conn: Connection) -> usize {
        let mut inner = self.0.write().await;
        let id = inner.counter;
        inner.counter += 1;
        inner.id.insert(id, conn);
        id
    }

    pub async fn link(&self, id: usize, conn: Connection, mac: MACAddr) {
        let mut inner = self.0.write().await;
        inner.linked.insert(mac, (id, conn));
    }

    pub async fn unregister(&self, conn: usize) {
        let mut inner = self.0.write().await;
        inner.id.remove(&conn);
        inner.linked.retain(|_, v| v.0 != conn);
    }

    pub async fn send(&self, data: &[u8]) -> Result<(), SendError> {
        // Ignore failed connections
        let inner = self.0.read().await;
        let specific = data
            .get(0..6)
            .and_then(|s| inner.linked.get(&MACAddr(s.try_into().unwrap())));
        tracing::debug!("[SEND] {}", data.len());
        if let Some((_, conn)) = specific {
            Self::send_to(data, conn)
        } else {
            for (_, conn) in inner.id.iter() {
                let _ = Self::send_to(data, conn);
            }
            Ok(())
        }
    }

    fn send_to(data: &[u8], conn: &Connection) -> Result<(), SendError> {
        let cur_max_dgram_size = conn.max_datagram_size();
        if cur_max_dgram_size.is_none() {
            return Err(SendError::DgramDisabled);
        }

        let cur_max_dgram_size = cur_max_dgram_size.unwrap();
        
        if let Err(e) = conn.send_datagram(data.to_owned().into()) {
            tracing::warn!("[SEND {}] Failed: {}", conn.remote_address(), e);

            match e {
                quinn::SendDatagramError::TooLarge => Err(SendError::PacketTooBig{ mtu: cur_max_dgram_size }),
                e => Err(e.into())
            }
        } else {
            Ok(())
        }
    }
}
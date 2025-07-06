use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

use quinn::Connection;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MACAddr(pub [u8; 6]);

struct StoreInner {
    linked: HashMap<MACAddr, (usize, Connection)>,
    id: HashMap<usize, Connection>,
    counter: usize,
    
}

#[derive(Clone)]
pub struct Store(Arc<RwLock<StoreInner>>);

impl Store {
    pub fn new() -> Self {
        let inner = StoreInner {
            linked: HashMap::new(),
            id: HashMap::new(),
            counter: 0,
        };
        Store(Arc::new(RwLock::new(inner)))
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

    pub async fn send(&self, data: &[u8]) {
        // Ignore failed connections
        let inner = self.0.read().await;
        let specific = data.get(0..6).and_then(|s| {
            inner.linked.get(&MACAddr(s.try_into().unwrap()))
        });
        println!("==> {:?}", data);
        if let Some((_, conn)) = specific {
            if let Err(_e) = conn.send_datagram(data.to_owned().into()) {
                // TODO: log
            }
        } else {
            for (_, conn) in inner.id.iter() {
                if let Err(_e) = conn.send_datagram(data.to_owned().into()) {
                    // TODO: log
                }
            }
        }
    }
}

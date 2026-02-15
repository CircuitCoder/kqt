use std::sync::Arc;

use tokio::sync::RwLock;

use crate::backend::{NodeID, SendError, neighboor::Neighboors, node_id_of};

#[derive(Clone)]
pub struct Router {
    neighboors: Arc<RwLock<Neighboors>>,
}

impl Router {
    pub fn new(neighboors: Arc<RwLock<Neighboors>>) -> Self {
        Self { neighboors }
    }

    pub async fn send(&self, to: NodeID, pkt: &[u8]) -> Result<(), SendError> {
        let neighboors = self.neighboors.read().await;
        for neigh in neighboors.iter() {
            if node_id_of(&neigh.identity) == to {
                return neigh.send(pkt);
            }
        }
        return Err(SendError::Unreachable);
    }

    pub async fn broadcast(&self, pkt: &[u8]) -> Result<(), SendError> {
        // Broadcasting will supress all individual errors
        let neighboors = self.neighboors.read().await;
        for neigh in neighboors.iter() {
            let _ = neigh.send(pkt);
        }
        Ok(())
    }
}

// Right now, only P2P mode
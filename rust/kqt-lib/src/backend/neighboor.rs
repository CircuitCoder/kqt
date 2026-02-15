use ed25519_dalek::VerifyingKey;
use quinn::{Connection, VarInt};

use crate::backend::SendError;

pub struct Neighboor {
    pub(crate) identity: VerifyingKey,
    pub(crate) outgoing: Option<Connection>,
    pub(crate) incoming: Option<Connection>,
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

pub struct Neighboors {
    neighboors: Vec<Neighboor>,
}

impl Neighboors {
    pub fn new() -> Self {
        Self { neighboors: Vec::new() }
    }

    pub fn find_neighboor(&mut self, to: &VerifyingKey) -> &mut Neighboor {
        for i in 0..self.neighboors.len() {
            if self.neighboors[i].identity == *to {
                return &mut self.neighboors[i];
            }
        }

        self.neighboors.push(Neighboor {
            identity: to.clone(),
            outgoing: None,
            incoming: None,
        });
        self.neighboors.last_mut().unwrap()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Neighboor> {
        self.neighboors.iter()
    }
}

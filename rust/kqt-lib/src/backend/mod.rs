use ed25519_dalek::VerifyingKey;
use quinn::SendDatagramError;
use thiserror::Error;

pub mod neighboor;
pub mod resolver;
pub mod router;
pub mod engine;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MACAddr(pub [u8; 6]);

pub type NodeID = u32;

#[derive(Eq, PartialEq, Clone, Copy)]
#[repr(transparent)]
pub struct SeqNo(u16);

impl Ord for SeqNo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.0 == other.0 {
            return std::cmp::Ordering::Equal;
        }
        return if other.0.wrapping_sub(self.0) < 0x8000 {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        };
    }
}

impl PartialOrd for SeqNo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

fn node_id_of(vk: &VerifyingKey) -> NodeID {
    let bytes = vk.as_bytes();
    u32::from_le_bytes(bytes[0..4].try_into().unwrap())
}

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
    #[error("malformed packet")]
    MalformedPkt,
    #[error("unknown error")]
    Unknown(#[from] SendDatagramError),
}
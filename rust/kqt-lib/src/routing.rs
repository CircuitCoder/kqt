// An implementation of a BABEL(RFC8966)-like routing protocol

use std::net::IpAddr;

use crate::peers::MACAddr;

#[derive(Eq, PartialEq, Clone)]
struct SeqNo(u16);

struct tmp {
    tmp: std::collections::BTreeMap<IpAddr, SeqNo>,
}

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

#[derive(Eq, PartialEq, Clone)]
struct Distance {
    metric: u64,
    seq: SeqNo,
}

impl Distance {
    pub fn is_feasible(&self, fd: &Distance) -> bool {
        return self.seq > fd.seq || (self.seq == fd.seq && self.metric < fd.metric);
    }
}

trait Target: PartialOrd + Ord + PartialEq + Eq {}

// L3 flat mesh
impl Target for IpAddr {}
// L2 flat mesh
impl Target for MACAddr {}
// TODO: add L3 advertised

// FIXME: Host identifier

struct State {
    fd: Option<Distance>,
}

use std::{collections::BTreeMap, net::IpAddr, sync::Arc};

use cidr::{IpInet, Ipv4Inet, Ipv6Inet};
use ed25519_dalek::VerifyingKey;
use tokio::sync::RwLock;

use crate::{backend::{MACAddr, NodeID, SeqNo, node_id_of}, config::Mode, packet::ip_is_v4};

const fn const_unwrap<T, E>(r: Result<T, E>) -> T {
    match r {
        Ok(v) => v,
        Err(_e) => panic!("Const unwrap failed"),
    }
}
const MINIMAL_IPV4_INET: Ipv4Inet =
    const_unwrap(Ipv4Inet::new(std::net::Ipv4Addr::from([0; 4]), 0));
const MINIMAL_IPV6_INET: Ipv6Inet =
    const_unwrap(Ipv6Inet::new(std::net::Ipv6Addr::from([0; 16]), 0));

#[derive(Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
struct L2ResolverKey {
    mac: MACAddr,
    target: NodeID,
}

struct L2ResolverEntry {
    target: NodeID,
    recorded_at: std::time::Instant,
}

pub struct L2ResolverImpl {
    mappings: BTreeMap<L2ResolverKey, L2ResolverEntry>,
}

impl L2ResolverImpl {
    fn lookup(&self, t: &MACAddr) -> Option<&L2ResolverEntry> {
        let key = L2ResolverKey { mac: *t, target: 0 };
        let mut it = self.mappings.upper_bound(std::ops::Bound::Excluded(&key));
        while let Some((k, l)) = it.next() && k.mac == *t {
            if l.recorded_at.elapsed() < ENTRY_TIMEOUT {
                return Some(l);
            }
        }
        None
    }

    pub fn update(&mut self, from: NodeID, mac: MACAddr) {
        let target = L2ResolverKey { mac, target: from };
        self.mappings.insert(target, L2ResolverEntry {
            target: from,
            recorded_at: std::time::Instant::now(),
        });
    }
}

const BROADCAST_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
const ENTRY_TIMEOUT: std::time::Duration = BROADCAST_INTERVAL * 5;
const TOMBSTONE_TIMEOUT: std::time::Duration = BROADCAST_INTERVAL * 10;

#[derive(Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
struct L3ResolverKey {
    range: IpInet,
    target: NodeID,
}

struct L3ResolverEntry {
    target: NodeID,
    recorded_at: std::time::Instant,
    seqno: SeqNo,
    metric: u16,
}

pub struct L3ResolverImpl {
    mappings: BTreeMap<L3ResolverKey, L3ResolverEntry>,
}

impl L3ResolverImpl {
    fn lookup(&self, t: &IpAddr) -> Option<&L3ResolverEntry> {
        let minimal: IpInet = if t.is_ipv4() {
            MINIMAL_IPV4_INET.into()
        } else {
            MINIMAL_IPV6_INET.into()
        };

        // Later = longer prefixes = wins
        let key = L3ResolverKey {
            range: minimal,
            target: 0,
        };
        let mut it = self.mappings.upper_bound(std::ops::Bound::Excluded(&key));
        let mut lookup = None;
        let mut found_length = 0;
        let mut found_metric = u16::MAX;
        while let Some((r, l)) = it.next()
            && r.range.is_ipv4() == t.is_ipv4()
        {
            if l.recorded_at.elapsed() >= ENTRY_TIMEOUT {
                continue;
            }

            // Skip same length, as that means larger metric
            if lookup.is_some() {
                if r.range.network_length() <= found_length {
                    continue;
                }

                if l.metric >= found_metric {
                    continue;
                }
            }

            if r.range.contains(t) {
                lookup = Some(l);
                found_length = r.range.network_length();
                found_metric = l.metric;
            }
        }
        lookup
    }
    pub fn update(&mut self, from: NodeID, entries: impl Iterator<Item = (IpInet, SeqNo, u16)>) {
        use std::collections::btree_map::Entry::*;
        let now = std::time::Instant::now();
        for (network, seqno, metric) in entries {
            let target = L3ResolverKey {
                range: network,
                target: from,
            };
            let entry = self.mappings.entry(target);
            if metric == u16::MAX {
                // Tombstone
                if let Occupied(e) = entry {
                    if e.get().seqno < seqno {
                        e.remove();
                    }
                }
            } else {
                let new_entry = L3ResolverEntry {
                    target: from.clone(),
                    seqno: seqno,
                    recorded_at: now,
                    metric: metric,
                };
                match entry {
                    Occupied(mut e) => {
                        if e.get().seqno < seqno {
                            e.insert(new_entry);
                        }
                    }
                    Vacant(e) => {
                        e.insert(new_entry);
                    }
                };
            }
        }
    }
}

#[derive(Clone)]
pub enum Resolver {
    L2(Arc<RwLock<L2ResolverImpl>>),
    L3(Arc<RwLock<L3ResolverImpl>>),
}

pub enum ResolveResult {
    Unicast(NodeID),
    Broadcast,
    Unreachable,
    MalformedPkt,
}

impl Resolver {
    pub fn new(mode: Mode) -> Self {
        match mode {
            Mode::L2 => Resolver::L2(Arc::new(RwLock::new(L2ResolverImpl { mappings: BTreeMap::new() }))),
            Mode::L3 => Resolver::L3(Arc::new(RwLock::new(L3ResolverImpl { mappings: BTreeMap::new() }))),
        }
    }

    pub async fn lookup(&self, pkt: &[u8]) -> ResolveResult {
        match self {
            Resolver::L2(r) => {
                let Some(mac) = pkt.get(0..6).and_then(|s| s.try_into().ok()) else {
                    return ResolveResult::MalformedPkt;
                };

                if mac == [0xff; 6] {
                    return ResolveResult::Broadcast;
                }

                match r.read().await.lookup(&MACAddr(mac)) {
                    Some(e) => ResolveResult::Unicast(e.target),
                    // In L2 mode, if not found, broadcast
                    None => ResolveResult::Broadcast,
                }
            }
            Resolver::L3(r) => {
                let addr = if ip_is_v4(pkt) {
                    let Some(addr): Option<[u8; 4]> = pkt.get(16..20).and_then(|s| s.try_into().ok()) else {
                        return ResolveResult::MalformedPkt;
                    };

                    if addr[0] & 0xf0 == 0xe0 {
                        return ResolveResult::Broadcast;
                    }

                    IpAddr::V4(addr.into())
                } else {
                    let Some(addr): Option<[u8; 16]> = pkt.get(24..40).and_then(|s| s.try_into().ok()) else {
                        return ResolveResult::MalformedPkt;
                    };

                    if addr[0] == 0xff {
                        return ResolveResult::Broadcast;
                    }

                    IpAddr::V6(addr.into())
                };

                match r.read().await.lookup(&addr) {
                    Some(e) => ResolveResult::Unicast(e.target),
                    None => ResolveResult::Unreachable,
                }
            }
        }
    }

    pub async fn ingress(&self, from: &VerifyingKey, pkt: &[u8]) {
        let from = node_id_of(from);
        match self {
            Resolver::L2(r) => {
                let Some(mac) = pkt.get(6..12).and_then(|s| s.try_into().ok()) else {
                    return;
                };
                let mac = MACAddr(mac);
                // TODO: check if r already has an entry. Skip write locking
                r.write().await.update(from, mac);
            },
            Resolver::L3(_r) => {
                // TODO: parse announcement pkt
                return;
            }
        }
    }
}
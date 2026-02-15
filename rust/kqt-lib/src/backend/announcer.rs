use std::sync::Arc;

use cidr::IpInet;
use tokio::{select, sync::{mpsc, watch}};

use crate::backend::{SeqNo, router::{NodePath, Router}};

pub const ANNOUNCE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
pub const TOMBSTONE_TIMEOUT: std::time::Duration = ANNOUNCE_INTERVAL * 10;

pub struct L3Announcer {
    announcing: watch::Receiver<Arc<Vec<(IpInet, u16)>>>,

    // Doubles as a cancel signal for the announcer task
    join: mpsc::Receiver<NodePath>,

    seqno: SeqNo,

    // TODO: tombstones
}

#[derive(Clone)]
pub struct L3AnnouncerHandle {
    pub announcing: watch::Sender<Arc<Vec<(IpInet, u16)>>>,
    pub join: mpsc::Sender<NodePath>,
}

// FIXME: seqno
impl L3Announcer {
    async fn send_to(&self, router: &Router, node: NodePath, ips: &[(IpInet, u16)], buf: &mut Vec<u8>) {
        tracing::debug!("Announcing to node {}: {} IPs", node.node, ips.len());
        let Some(mtu) = node.mtu else { return };
        if mtu < 1000 { return }

        buf.resize(mtu, 0);

        // We necessarily operates in L3 mode (since we're announcing IPs)
        // So let's fill at most MTU bytes with IPs

        // First byte, IP version and IHL. We use 5 and 0 to mark an announcement
        buf[0] = 0x50;

        // Second byte will be filled as the number of IPs in this packet

        // Byte 3 ~ 4 is seqno
        buf[2..4].copy_from_slice(&self.seqno.0.to_be_bytes());

        // Where to write the next IP network
        let mut ptr = 4;
        let mut counter = 0;

        for i in 0..ips.len() {
            let net = &ips[i];
            loop {
                // Try to serialize
                let Some(len) = serialize_ipinet_into(&mut buf[ptr..], net) else {
                    // Not enough space
                    buf[1] = counter;

                    // Ignore error
                    let _ = router.send(node.node, &buf[..ptr]).await;

                    ptr = 4;
                    counter = 0;

                    // Retry
                    continue;
                };
                ptr += len;
                counter += 1;
                break;
            }
        }
        if counter > 0 {
            buf[1] = counter;
            let _ = router.send(node.node, &buf[..ptr]).await;
        }
    }

    async fn broadcast(&mut self, router: &Router, buf: &mut Vec<u8>) {
        let newest = self.announcing.borrow_and_update().clone();
        let nodes = router.live_nodes().await;

        for node in nodes {
            self.send_to(router, node, &newest, buf).await;
        }
    }

    async fn announct_to(&self, router: &Router, node: NodePath) {
        let newest = self.announcing.borrow().clone();
        self.send_to(router, node, &newest, &mut Vec::new()).await
    }

    async fn run(&mut self, router: &Router) {
        let mut buf = Vec::new();
        loop {
            select! {
                _ = tokio::time::sleep(ANNOUNCE_INTERVAL) => {
                    self.broadcast(router, &mut buf).await;
                },
                _ = self.announcing.changed() => {
                    self.seqno.inc();
                    self.broadcast(router, &mut buf).await;
                },
                node = self.join.recv() => {
                    if let Some(node) = node {
                        self.announct_to(router, node).await;
                    } else {
                        // All senders are dropped, we can stop the announcer
                        break;
                    }
                }
            }

        }
    }
}

pub fn spawn(router: Router) -> L3AnnouncerHandle {
    let (announcing_tx, announcing_rx) = watch::channel(Arc::new(Vec::new()));
    let (join_tx, join_rx) = mpsc::channel(16);

    let mut announcer = L3Announcer {
        announcing: announcing_rx,
        join: join_rx,
        seqno: SeqNo(0),
    };

    tokio::spawn(async move {
        announcer.run(&router).await;
    });

    L3AnnouncerHandle {
        announcing: announcing_tx,
        join: join_tx,
    }
}

pub fn serialize_ipinet_into(buf: &mut [u8], prefix: &(IpInet, u16)) -> Option<usize> {
    // First byte: type of the IP address
    // Second byte: network length
    // Next two bytes, metric
    // Next bytes: the IP address

    let len = 4 + match prefix.0 {
        IpInet::V4(_) => 4,
        IpInet::V6(_) => 16,
    };

    if buf.len() < len {
        return None;
    }

    let first_byte = match prefix.0 {
        IpInet::V4(_) => 0,
        IpInet::V6(_) => 1,
    };
    buf[0] = first_byte;
    buf[1] = prefix.0.network_length() as u8;
    buf[2..4].copy_from_slice(&prefix.1.to_be_bytes());

    match prefix.0 {
        IpInet::V4(ipv4) => buf[4..8].copy_from_slice(&ipv4.address().octets()),
        IpInet::V6(ipv6) => buf[4..20].copy_from_slice(&ipv6.address().octets()),
    }

    Some(len)
}

pub fn deserialize_ipinet_from(buf: &[u8]) -> Option<((IpInet, u16), usize)> {
    if buf.len() < 4 {
        return None;
    }

    let ip_type = buf[0];
    let network_length = buf[1] as u8;
    let metric = u16::from_be_bytes(buf[2..4].try_into().unwrap());
    
    match ip_type {
        0 => {
            let addr: [u8; 4] = buf.get(4..8)?.try_into().unwrap();
            let ipv4 = std::net::Ipv4Addr::from(addr);
            IpInet::new(ipv4.into(), network_length).ok().map(|ip| ((ip, metric), 8))
        }
        1 => {
            let addr: [u8; 16] = buf.get(4..20)?.try_into().unwrap();
            let ipv6 = std::net::Ipv6Addr::from(addr);
            IpInet::new(ipv6.into(), network_length).ok().map(|ip| ((ip, metric), 20))
        }
        _ => None,
    }
}

pub fn deserialize_announcement(announcement: &[u8]) -> Option<(SeqNo, usize, impl Iterator<Item = (IpInet, u16)>)> {
    if announcement.len() < 4 {
        return None;
    }

    let seqno = SeqNo(u16::from_be_bytes(announcement[2..4].try_into().unwrap()));
    let total = announcement[1] as usize;
    let mut ptr = 4;
    let mut counter = 0;

    let it = std::iter::from_fn(move || {
        if counter >= total {
            return None;
        }

        let ((ip, metric), len) = deserialize_ipinet_from(&announcement[ptr..])?;
        ptr += len;
        counter += 1;
        return Some((ip, metric));
    });

    Some((seqno, total, it))
}
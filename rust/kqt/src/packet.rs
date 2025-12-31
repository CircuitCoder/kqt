use std::borrow::Cow;

use rand_core::RngCore;

const ETH_HDR_LEN: usize = 14;
const IPV4_HDR_LEN: usize = 20;
const IPV4_HDR_LEN_ENCODED: u8 = 5;
const ICMPV4_DESTINATION_UNREACHABLE_LEN: usize = 8;
const IPV6_HDR_LEN: usize = 40;
const ICMPV6_PACKET_TOO_BIG_WITH_MTU_LEN: usize = 8;
pub const FRONT_BUFFER: usize = std::cmp::max(
    IPV4_HDR_LEN + ICMPV4_DESTINATION_UNREACHABLE_LEN,
    IPV6_HDR_LEN + ICMPV6_PACKET_TOO_BIG_WITH_MTU_LEN,
);

fn invert_eth_header(src: &[u8], dst: &mut [u8]) {
    dst[0..6].copy_from_slice(&src[6..12]);
    dst[6..12].copy_from_slice(&src[0..6]);
    dst[12..14].copy_from_slice(&src[12..14]);
}

fn populate_ipv4_packet_too_big(
    outer_mtu: usize,
    buf: &mut [u8],
    pkt_start: usize,
    pkt_len: usize,
) -> anyhow::Result<Option<&[u8]>> {
    use pnet::packet::Packet;
    use pnet::packet::icmp::IcmpTypes;
    use pnet::packet::icmp::destination_unreachable::{
        IcmpCodes, MutableDestinationUnreachablePacket,
    };
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet};

    let Some(ipv4_orig) = Ipv4Packet::new(&buf[pkt_start + ETH_HDR_LEN..]) else {
        return Ok(None);
    };
    if ipv4_orig.get_flags() & Ipv4Flags::DontFragment == 0 {
        // No need for ICMP, simply drop
        return Ok(None);
    }
    // Swap src & dst
    let ipv4_src = ipv4_orig.get_destination();
    let ipv4_dst = ipv4_orig.get_source();

    // Move ethernet header backward
    let new_pkt_start = pkt_start - (IPV4_HDR_LEN + ICMPV4_DESTINATION_UNREACHABLE_LEN);
    let (pkt_front, pkt_back) = buf.split_at_mut(pkt_start);
    let eth_src = &pkt_back[..ETH_HDR_LEN];
    let eth_dst: &mut [u8] = &mut pkt_front[new_pkt_start..new_pkt_start + ETH_HDR_LEN];
    invert_eth_header(eth_src, eth_dst);

    // Re-split buffer
    let eth_buf = &mut buf[new_pkt_start..];
    let ipv4_buf = &mut eth_buf[ETH_HDR_LEN..];

    let icmpv4_payload_len = (pkt_len - ETH_HDR_LEN).min(568);
    let ipv4_payload_len = ICMPV4_DESTINATION_UNREACHABLE_LEN + icmpv4_payload_len;
    let ipv4_total_len = IPV4_HDR_LEN + ipv4_payload_len;

    // Prepare ICMPv4 Destination Unreachable (Fragmentation Needed and DF set)
    let icmpv4_buf = &mut ipv4_buf[IPV4_HDR_LEN..];
    let mut icmpv4 =
        MutableDestinationUnreachablePacket::new(icmpv4_buf).expect("Buffer too short for icmpv4");

    icmpv4.set_icmp_type(IcmpTypes::DestinationUnreachable);
    icmpv4.set_icmp_code(IcmpCodes::FragmentationRequiredAndDFFlagSet);
    icmpv4.set_unused(0);
    icmpv4.set_next_hop_mtu((outer_mtu - ETH_HDR_LEN) as u16);

    // Compute ICMP checksum
    let icmpv4_chksum = pnet::packet::util::checksum(&icmpv4.packet()[..ipv4_payload_len], 1);
    icmpv4.set_checksum(icmpv4_chksum);

    // Prepare IPv4 header
    let mut ipv4 = MutableIpv4Packet::new(ipv4_buf).expect("Buffer too short for ipv4");
    ipv4.set_version(4);
    ipv4.set_source(ipv4_src);
    ipv4.set_destination(ipv4_dst);
    // Set other fields
    ipv4.set_header_length(IPV4_HDR_LEN_ENCODED);
    ipv4.set_dscp(0);
    ipv4.set_ecn(0);
    ipv4.set_identification(rand_core::OsRng.next_u32() as u16);
    ipv4.set_flags(0);
    ipv4.set_fragment_offset(0);
    ipv4.set_ttl(64);
    ipv4.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4.set_total_length(ipv4_total_len as u16);

    let ipv4_chksum = pnet::packet::ipv4::checksum(&ipv4.to_immutable());
    ipv4.set_checksum(ipv4_chksum);

    Ok(Some(
        &buf[new_pkt_start..new_pkt_start + ETH_HDR_LEN + ipv4_total_len],
    ))
}

fn populate_ipv6_packet_too_big(
    outer_mtu: usize,
    buf: &mut [u8],
    pkt_start: usize,
    pkt_len: usize,
) -> anyhow::Result<Option<&[u8]>> {
    use pnet::packet::Packet;
    use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Types, MutableIcmpv6Packet};
    use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};

    // Assert that we have enough space for the header
    assert!(pkt_start >= IPV6_HDR_LEN + ICMPV6_PACKET_TOO_BIG_WITH_MTU_LEN);

    let Some(ipv6_orig) = Ipv6Packet::new(&buf[pkt_start + ETH_HDR_LEN..]) else {
        return Ok(None);
    };
    // Swap src & dst
    let ipv6_src = ipv6_orig.get_destination();
    let ipv6_dst = ipv6_orig.get_source();

    // Move ethernet header backward
    let new_pkt_start = pkt_start - (IPV6_HDR_LEN + ICMPV6_PACKET_TOO_BIG_WITH_MTU_LEN);
    let (pkt_front, pkt_back) = buf.split_at_mut(pkt_start);
    let eth_src = &pkt_back[..ETH_HDR_LEN];
    let eth_dst: &mut [u8] = &mut pkt_front[new_pkt_start..new_pkt_start + ETH_HDR_LEN];
    invert_eth_header(eth_src, eth_dst);

    // Re-split buffer
    let eth_buf = &mut buf[new_pkt_start..];
    let ipv6_buf = &mut eth_buf[ETH_HDR_LEN..];

    let icmpv6_payload_len = (pkt_len - ETH_HDR_LEN).min(1232);
    let ipv6_payload_len = ICMPV6_PACKET_TOO_BIG_WITH_MTU_LEN + icmpv6_payload_len;

    // Copy up to 1232 bytes of the original packet as payload
    let icmpv6_buf = &mut ipv6_buf[IPV6_HDR_LEN..];
    (&mut icmpv6_buf[4..8]).copy_from_slice(&((outer_mtu - ETH_HDR_LEN) as u32).to_be_bytes());
    let mut icmpv6 = MutableIcmpv6Packet::new(icmpv6_buf).expect("Buffer too short for icmpv6");
    icmpv6.set_icmpv6_type(Icmpv6Types::PacketTooBig);
    icmpv6.set_icmpv6_code(Icmpv6Code(0));

    // Compute ICMPv6 checksum
    let checksum = pnet::packet::util::ipv6_checksum(
        &icmpv6.packet()[..icmpv6_payload_len],
        1,
        &[],
        &ipv6_src,
        &ipv6_dst,
        pnet::packet::ip::IpNextHeaderProtocols::Icmpv6,
    );
    icmpv6.set_checksum(checksum);

    // Prepare ICMPv6 Packet Too Big
    let mut ipv6 = MutableIpv6Packet::new(ipv6_buf)
        .ok_or_else(|| anyhow::anyhow!("Buffer too short for ipv6"))?;
    ipv6.set_source(ipv6_src);
    ipv6.set_destination(ipv6_dst);
    // Set other fields
    ipv6.set_version(6);
    ipv6.set_traffic_class(0);
    ipv6.set_flow_label(0);
    ipv6.set_hop_limit(64);
    ipv6.set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Icmpv6);
    ipv6.set_payload_length(ipv6_payload_len as u16);

    Ok(Some(
        &buf[new_pkt_start..new_pkt_start + ETH_HDR_LEN + IPV6_HDR_LEN + ipv6_payload_len],
    ))
}

pub fn populate_packet_too_big(
    outer_mtu: usize,
    buf: &mut [u8],
    pkt_start: usize,
    pkt_len: usize,
) -> anyhow::Result<Option<&[u8]>> {
    match buf.get(pkt_start + ETH_HDR_LEN) {
        Some(b) if (b >> 4) == 4 => {
            populate_ipv4_packet_too_big(outer_mtu, buf, pkt_start, pkt_len)
        }
        Some(b) if (b >> 4) == 6 => {
            populate_ipv6_packet_too_big(outer_mtu, buf, pkt_start, pkt_len)
        }
        _ => Ok(None),
    }
}

fn is_v4(packet: &[u8]) -> bool {
    packet
        .get(ETH_HDR_LEN)
        .map(|b| (b >> 4) == 4)
        .unwrap_or(false)
}

pub fn can_frag(packet: &[u8]) -> bool {
    if !is_v4(packet) {
        return false;
    }

    use pnet::packet::ipv4::Ipv4Packet;
    let Some(ipv4) = Ipv4Packet::new(&packet[ETH_HDR_LEN..]) else {
        return false;
    };

    return (ipv4.get_flags() & pnet::packet::ipv4::Ipv4Flags::DontFragment) == 0;
}

pub fn frag_if_needed(
    outer_mtu: usize,
    packet: &mut [u8],
    orig_frag: bool,
) -> anyhow::Result<&[u8]> {
    let needs_frag = packet.len() > outer_mtu;
    let final_len = if needs_frag {
        // Calculate fragment size (must be multiple of 8)
        let frag_size = (outer_mtu - ETH_HDR_LEN - IPV4_HDR_LEN) & !7;
        assert!(frag_size >= 8);
        ETH_HDR_LEN + IPV4_HDR_LEN + frag_size
    } else {
        packet.len()
    };

    if !is_v4(packet) {
        // Not IPv4, nothing to do
        return Ok(packet);
    }

    use pnet::packet::ipv4::MutableIpv4Packet;
    let mut ipv4 = MutableIpv4Packet::new(&mut packet[ETH_HDR_LEN..])
        .ok_or_else(|| anyhow::anyhow!("Invalid IPv4 packet"))?;
    let flags = if needs_frag || orig_frag {
        // Set More Fragments flag if we are fragmenting or if the original packet was fragmented
        ipv4.get_flags() | pnet::packet::ipv4::Ipv4Flags::MoreFragments
    } else {
        ipv4.get_flags() & !pnet::packet::ipv4::Ipv4Flags::MoreFragments
    };
    ipv4.set_flags(flags);
    ipv4.set_total_length((final_len - ETH_HDR_LEN) as u16);
    // Reconculate checksum
    let chksum = pnet::packet::ipv4::checksum(&ipv4.to_immutable());
    ipv4.set_checksum(chksum);
    Ok(&packet[..final_len])
}

pub fn has_more_frag(packet: &[u8]) -> bool {
    if !is_v4(packet) {
        return false;
    }

    use pnet::packet::ipv4::Ipv4Packet;
    let Some(ipv4) = Ipv4Packet::new(&packet[ETH_HDR_LEN..]) else {
        return false;
    };

    (ipv4.get_flags() & pnet::packet::ipv4::Ipv4Flags::MoreFragments) != 0
}

pub fn move_frag_headers(sent: usize, packet: &mut [u8]) -> &mut [u8] {
    assert!(is_v4(packet));
    assert!(sent > ETH_HDR_LEN + IPV4_HDR_LEN);
    let dist = sent - (ETH_HDR_LEN + IPV4_HDR_LEN);
    packet.copy_within(..ETH_HDR_LEN + IPV4_HDR_LEN, dist);
    let new_pkt = &mut packet[dist..];
    // Bump fragment offset
    use pnet::packet::ipv4::MutableIpv4Packet;
    let mut ipv4 =
        MutableIpv4Packet::new(&mut new_pkt[ETH_HDR_LEN..]).expect("Invalid IPv4 packet");
    let old_offset = ipv4.get_fragment_offset();
    assert!(dist % 8 == 0);
    let new_offset = old_offset + (dist / 8) as u16;
    ipv4.set_fragment_offset(new_offset);
    new_pkt
}

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{TcpOptionNumbers, TcpPacket};

/// Clamps the TCP MSS option in an Ethernet frame to the specified value.
/// Updates the TCP checksum incrementally if modification is performed.
/// Returns the indices of the MSS option and the chksum
pub fn clamp_mss<'s>(pkt: &'s [u8], outer_mtu: usize) -> Cow<'s, [u8]> {
    let mut pkt = Cow::Borrowed(pkt);
    // Parse IP Header and find start of TCP
    let Some(ip_ver) = pkt.get(ETH_HDR_LEN).map(|b| b >> 4) else {
        return pkt;
    };
    let tcp_offset = match ip_ver {
        4 => {
            let Some(ipv4) = Ipv4Packet::new(&pkt[ETH_HDR_LEN..]) else {
                return pkt;
            };
            if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                return pkt;
            }
            ETH_HDR_LEN + ipv4.get_header_length() as usize * 4
        }
        6 => {
            let Some(ipv6) = Ipv6Packet::new(&pkt[ETH_HDR_LEN..]) else {
                return pkt;
            };
            if ipv6.get_next_header() != IpNextHeaderProtocols::Tcp {
                return pkt;
            }
            ETH_HDR_LEN + IPV6_HDR_LEN
        }
        _ => return pkt, // Unknown IP version
    };
    let tcp_pkt = &pkt[tcp_offset..];

    // We create a scope here to borrow the TCP portion mutably
    let tcp = match TcpPacket::new(tcp_pkt) {
        Some(t) => t,
        None => return pkt,
    };

    // Calculate TCP Options length: (Data Offset * 4) - 20 bytes fixed header
    let data_offset = tcp.get_data_offset();
    let tcp_header_len = (data_offset as usize) * 4;

    if tcp_header_len <= 20 {
        return pkt; // No options present
    }

    let options_len = tcp_header_len - 20;

    // 4. Iterate over TCP Options
    // We access the raw byte slice of the options to avoid expensive Vec allocation
    let mut i = 0;

    // The options start at byte 20 of the TCP header
    while i < options_len {
        // Option offset relative to TCP header start
        let opt_idx: usize = 20 + i;

        // Safety check bounds
        let Some(kind) = tcp_pkt.get(opt_idx).copied() else {
            break;
        };

        if kind == 0 {
            break; // EOL (End of List)
        }

        if kind == 1 {
            // NOP (No Operation), length 1
            i += 1;
            continue;
        }

        // TLV Options (Type, Length, Value)
        let Some(len) = tcp_pkt.get(opt_idx + 1).copied() else {
            break;
        };
        let len = len as usize;

        // Malformed option length checks
        if len < 2 || opt_idx + len > 20 + options_len {
            break;
        }

        // Check for MSS Option (Kind = 2, Length = 4)
        if kind == TcpOptionNumbers::MSS.0 && len == 4 {
            // Extract current MSS (Big Endian)
            let old_mss = u16::from_be_bytes(tcp_pkt[opt_idx + 2..opt_idx + 4].try_into().unwrap());
            let target_mss = (outer_mtu - tcp_offset - 20) as u16;

            if old_mss > target_mss {
                // 5. Update MSS and Checksum
                // Write new MSS
                let new_mss_bytes = target_mss.to_be_bytes();
                let tcp_pkt_mut = &mut pkt.to_mut()[tcp_offset..];
                tcp_pkt_mut[opt_idx + 2] = new_mss_bytes[0];
                tcp_pkt_mut[opt_idx + 3] = new_mss_bytes[1];

                // Read current checksum
                let old_csum = u16::from_be_bytes([tcp_pkt_mut[16], tcp_pkt_mut[17]]);

                // Calculate new checksum incrementally (RFC 1624 Eq. 3)
                // HC' = ~(~HC + ~m + m')
                let new_csum = checksum_incremental_update(old_csum, old_mss, target_mss);

                // Write new checksum
                let new_csum_bytes = new_csum.to_be_bytes();
                tcp_pkt_mut[16] = new_csum_bytes[0];
                tcp_pkt_mut[17] = new_csum_bytes[1];

                // We found and updated the MSS, we can stop
                return pkt;
            }
        }

        i += len;
    }
    pkt
}

/// Implements incremental checksum update (RFC 1624).
///
/// `old_csum`: The original checksum field value.
/// `old_val`: The 16-bit value that was replaced.
/// `new_val`: The 16-bit value that replaced `old_val`.
fn checksum_incremental_update(old_csum: u16, old_val: u16, new_val: u16) -> u16 {
    // 1. Negate the old checksum (one's complement)
    let csum_not = (!old_csum) as u32;

    // 2. Add the negation of the old value (effectively subtracting it)
    let old_val_not = (!old_val) as u32;

    // 3. Add the new value
    let new_val_u32 = new_val as u32;

    let mut sum = csum_not + old_val_not + new_val_u32;

    // Fold carry bits
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16); // Fold again in case the first fold created a carry

    // Invert the result
    !(sum as u16)
}

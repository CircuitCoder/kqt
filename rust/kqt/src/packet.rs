use rand_core::RngCore;

const IPV4_HDR_LEN: usize = 20;
const IPV4_HDR_LEN_ENCODED: u8 = 5;

fn populate_ipv4_packet_too_big(
    mtu: usize,
    orig: &[u8],
    buf: &mut [u8],
) -> anyhow::Result<Option<usize>> {
    use pnet::packet::Packet;
    use pnet::packet::icmp::IcmpTypes;
    use pnet::packet::icmp::destination_unreachable::{
        IcmpCodes, MutableDestinationUnreachablePacket,
    };
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet};

    let Some(ipv4_orig) = Ipv4Packet::new(orig) else {
        return Ok(None);
    };
    if ipv4_orig.get_flags() & Ipv4Flags::DontFragment == 0 {
        // No need for ICMP, simply drop
        return Ok(None);
    }
    let icmpv4_payload = orig.get(..568).unwrap_or(orig);
    let tot_length = 20 + 8 + icmpv4_payload.len();
    if buf.len() < tot_length {
        return Err(anyhow::anyhow!("Buffer too short for icmpv4 payload"));
    }

    // Prepare ICMPv4 Destination Unreachable (Fragmentation Needed and DF set)
    let icmpv4_buf = &mut buf[IPV4_HDR_LEN..];
    let mut icmpv4 =
        MutableDestinationUnreachablePacket::new(icmpv4_buf).expect("Buffer too short for icmpv4");

    icmpv4.set_icmp_type(IcmpTypes::DestinationUnreachable);
    icmpv4.set_icmp_code(IcmpCodes::FragmentationRequiredAndDFFlagSet);
    icmpv4.set_unused(0);
    icmpv4.set_next_hop_mtu(mtu as u16);
    icmpv4.set_payload(icmpv4_payload);
    // Compute ICMP checksum
    let icmpv4_chksum =
        pnet::packet::util::checksum(&icmpv4.packet()[..(8 + icmpv4_payload.len())], 1);
    icmpv4.set_checksum(icmpv4_chksum);

    // Prepare IPv4 header
    let mut ipv4 = MutableIpv4Packet::new(buf).expect("Buffer too short for ipv4");
    ipv4.set_version(4);
    ipv4.set_source(ipv4_orig.get_destination());
    ipv4.set_destination(ipv4_orig.get_source());
    // Set other fields
    ipv4.set_header_length(IPV4_HDR_LEN_ENCODED);
    ipv4.set_dscp(0);
    ipv4.set_ecn(0);
    ipv4.set_identification(rand_core::OsRng.next_u32() as u16);
    ipv4.set_flags(0);
    ipv4.set_fragment_offset(0);
    ipv4.set_ttl(64);
    ipv4.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4.set_total_length(tot_length as u16);

    let ipv4_chksum = pnet::packet::ipv4::checksum(&ipv4.to_immutable());
    ipv4.set_checksum(ipv4_chksum);

    Ok(Some(tot_length))
}

fn populate_ipv6_packet_too_big(
    mtu: usize,
    orig: &[u8],
    buf: &mut [u8],
) -> anyhow::Result<Option<usize>> {
    use pnet::packet::Packet;
    use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Types, MutableIcmpv6Packet};
    use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};

    let Some(ipv6_orig) = Ipv6Packet::new(orig) else {
        return Ok(None);
    };

    let payload = orig.get(..1232).unwrap_or(orig);
    let payload_length = 4 + 4 + payload.len();
    let tot_length = 40 + payload_length;
    if buf.len() < tot_length {
        return Err(anyhow::anyhow!("Buffer too short for icmpv6 payload"));
    }

    // Copy up to 1232 bytes of the original packet as payload
    let icmpv6_buf = &mut buf[40..];
    let icmpv6_payload = &mut icmpv6_buf[4..];
    icmpv6_payload[0..4].copy_from_slice(&(mtu as u32).to_be_bytes());
    icmpv6_payload[4..(4 + payload.len())].copy_from_slice(payload);

    let mut icmpv6 = MutableIcmpv6Packet::new(icmpv6_buf).expect("Buffer too short for icmpv6");

    icmpv6.set_icmpv6_type(Icmpv6Types::PacketTooBig);
    icmpv6.set_icmpv6_code(Icmpv6Code(0));

    // Compute ICMPv6 checksum
    let ipv6_src = ipv6_orig.get_destination();
    let ipv6_dst = ipv6_orig.get_source();
    let checksum = pnet::packet::util::ipv6_checksum(
        &icmpv6.packet()[..(4 + 4 + payload.len())],
        1,
        &[],
        &ipv6_src,
        &ipv6_dst,
        pnet::packet::ip::IpNextHeaderProtocols::Icmpv6,
    );
    icmpv6.set_checksum(checksum);

    // Prepare ICMPv6 Packet Too Big
    let mut ipv6 =
        MutableIpv6Packet::new(buf).ok_or_else(|| anyhow::anyhow!("Buffer too short for ipv6"))?;
    ipv6.set_source(ipv6_src);
    ipv6.set_destination(ipv6_dst);
    // Set other fields
    ipv6.set_version(6);
    ipv6.set_traffic_class(0);
    ipv6.set_flow_label(0);
    ipv6.set_hop_limit(64);
    ipv6.set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Icmpv6);
    ipv6.set_payload_length(payload_length as u16);

    Ok(Some(tot_length))
}

pub fn populate_packet_too_big(
    mtu: usize,
    orig: &[u8],
    buf: &mut [u8],
) -> anyhow::Result<Option<usize>> {
    match orig.get(0) {
        Some(b) if (b >> 4) == 4 => populate_ipv4_packet_too_big(mtu, orig, buf),
        Some(b) if (b >> 4) == 6 => populate_ipv6_packet_too_big(mtu, orig, buf),
        _ => return Ok(None),
    }
}

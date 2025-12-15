use rand_core::RngCore;

fn populate_ipv4_packet_too_big(
    mtu: usize,
    orig: &[u8],
    buf: &mut [u8],
) -> anyhow::Result<Option<usize>> {
    use pnet::packet::icmp::IcmpTypes;
    use pnet::packet::icmp::destination_unreachable::{
        IcmpCodes, MutableDestinationUnreachablePacket,
    };
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet};
    use pnet::packet::{MutablePacket, Packet};

    let Some(ipv4_orig) = Ipv4Packet::new(orig) else {
        return Ok(None);
    };
    if ipv4_orig.get_flags() & Ipv4Flags::DontFragment == 0 {
        // No need for ICMP, simply drop
        return Ok(None);
    }

    // Prepare ICMPv4 Destination Unreachable (Fragmentation Needed and DF set)
    let mut ipv4 =
        MutableIpv4Packet::new(buf).ok_or_else(|| anyhow::anyhow!("Buffer too short"))?;
    ipv4.set_version(4);
    ipv4.set_source(ipv4_orig.get_destination());
    ipv4.set_destination(ipv4_orig.get_source());
    // Set other fields
    ipv4.set_header_length(5);
    ipv4.set_dscp(0);
    ipv4.set_ecn(0);
    ipv4.set_identification(rand_core::OsRng.next_u32() as u16);
    ipv4.set_flags(0);
    ipv4.set_fragment_offset(0);
    ipv4.set_ttl(64);

    // Checksum is calculated by the kernel
    // Total length will be set later

    // Set payload
    ipv4.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    let ipv4_payload = ipv4.payload_mut();
    let mut icmpv4 = MutableDestinationUnreachablePacket::new(ipv4_payload)
        .ok_or_else(|| anyhow::anyhow!("Buffer too short"))?;

    icmpv4.set_icmp_type(IcmpTypes::DestinationUnreachable);
    icmpv4.set_icmp_code(IcmpCodes::FragmentationRequiredAndDFFlagSet);
    icmpv4.set_unused(0);
    icmpv4.set_next_hop_mtu(mtu as u16);

    // Copy up to 568 bytes of the original packet as payload
    let icmpv4_payload = icmpv4.payload_mut();
    let payload = orig.get(..568).unwrap_or(orig);
    if icmpv4_payload.len() < payload.len() {
        return Err(anyhow::anyhow!("Buffer too short"));
    }
    icmpv4_payload[..payload.len()].copy_from_slice(payload);

    // Compute ICMP checksum
    let checksum = pnet::packet::util::checksum(&icmpv4.packet()[..(8 + payload.len())], 1);
    icmpv4.set_checksum(checksum);

    // Compute total length
    let tot_length = 20 + 8 + payload.len();
    ipv4.set_total_length(tot_length as u16);

    Ok(Some(tot_length))
}

fn populate_ipv6_packet_too_big(
    mtu: usize,
    orig: &[u8],
    buf: &mut [u8],
) -> anyhow::Result<Option<usize>> {
    use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Types, MutableIcmpv6Packet};
    use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
    use pnet::packet::{MutablePacket, Packet};

    let Some(ipv6_orig) = Ipv6Packet::new(orig) else {
        return Ok(None);
    };

    // Prepare ICMPv6 Packet Too Big
    let mut ipv6 =
        MutableIpv6Packet::new(buf).ok_or_else(|| anyhow::anyhow!("Buffer too short"))?;
    ipv6.set_source(ipv6_orig.get_destination());
    ipv6.set_destination(ipv6_orig.get_source());
    // Set other fields
    ipv6.set_version(6);
    ipv6.set_traffic_class(0);
    ipv6.set_flow_label(0);
    ipv6.set_hop_limit(64);

    // Payload length will be set later

    // Set payload
    ipv6.set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Icmpv6);
    let ipv6_payload = ipv6.payload_mut();
    let mut icmpv6 = MutableIcmpv6Packet::new(ipv6_payload)
        .ok_or_else(|| anyhow::anyhow!("Buffer too short"))?;

    icmpv6.set_icmpv6_type(Icmpv6Types::PacketTooBig);
    icmpv6.set_icmpv6_code(Icmpv6Code(0));

    // Copy up to 1232 bytes of the original packet as payload
    let icmpv6_payload = icmpv6.payload_mut();
    let payload = orig.get(..1232).unwrap_or(orig);
    if icmpv6_payload.len() < payload.len() + 4 {
        return Err(anyhow::anyhow!("Buffer too short for ICMPv6 payload"));
    }
    icmpv6_payload[0..4].copy_from_slice(&(mtu as u32).to_ne_bytes());
    icmpv6_payload[4..(4 + payload.len())].copy_from_slice(payload);

    // Compute ICMPv6 checksum
    let checksum = pnet::packet::util::checksum(&icmpv6.packet()[..(8 + 4 + payload.len())], 1);
    icmpv6.set_checksum(checksum);

    // Compute length
    let payload_length = 8 + 4 + payload.len();
    ipv6.set_payload_length(payload_length as u16);
    Ok(Some(40 + payload_length))
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

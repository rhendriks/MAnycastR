/// Parse TCP packets into a Reply result.
/// Only accepts packets with the RST flag set.
///
/// # Arguments
/// * `packet_bytes` - the bytes of the packet to parse
/// * `origin_map` - mapping of origin to origin ID
/// * `is_ipv6` - whether to parse the packet as IPv6 or IPv4
///
/// # Returns
/// * `Option<(Reply, bool)>` - the received TCP reply and whether it is a discovery packet
///
/// # Remarks
/// The function returns None if the packet is too short to contain a TCP header or if the RST flag is not set.
pub fn parse_tcp(
    packet_bytes: &[u8],
    origin_map: &Vec<Origin>,
    is_ipv6: bool,
) -> Option<(Reply, bool)> {
    // TCPv6 64 length (IPv6 header (40) + TCP header (20)) + check for RST flag
    // TCPv4 40 bytes (IPv4 header (20) + TCP header (20)) + check for RST flag
    if (is_ipv6 && (packet_bytes.len() < 60 || (packet_bytes[53] & 0x04) == 0))
        || (!is_ipv6 && (packet_bytes.len() < 40 || (packet_bytes[33] & 0x04) == 0))
    {
        return None;
    }

    let ip_header = if is_ipv6 {
        IPPacket::V6(IPv6Packet::from(packet_bytes))
    } else {
        IPPacket::V4(IPv4Packet::from(packet_bytes))
    };
    // cannot filter out spoofed packets as the probe_dst is unknown

    let PacketPayload::Tcp { value: tcp_packet } = ip_header.payload() else {
        return None;
    };

    let rx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;

    let origin_id = get_origin_id(
        ip_header.dst(),
        tcp_packet.sport,
        tcp_packet.dport,
        origin_map,
    )?;

    // Discovery probes have bit 16 set and higher bits unset
    let bit_16_mask = 1 << 16;
    let higher_bits_mask = !0u32 << 17;

    let (tx_id, is_discovery) =
        if (tcp_packet.seq & bit_16_mask) != 0 && (tcp_packet.seq & higher_bits_mask) == 0 {
            (tcp_packet.seq - u16::MAX as u32, true)
        } else {
            (tcp_packet.seq, false)
        };

    Some((
        Reply {
            tx_time: tx_id as u64,
            tx_id,
            src: Some(ip_header.src()),
            ttl: ip_header.ttl() as u32,
            rx_time,
            origin_id,
            chaos: None,
            trace_dst: None,
            trace_ttl: None,
            recorded_hops: vec![],
        },
        is_discovery,
    ))
}

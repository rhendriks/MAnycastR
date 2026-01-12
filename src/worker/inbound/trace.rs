use crate::custom_module::manycastr::reply::ReplyData;
use crate::custom_module::manycastr::{Address, Reply, TraceReply};
use crate::net::{ICMPPacket, IPPacket, IPv4Packet, IPv6Packet, PacketPayload};
use crate::worker::inbound::ping::parse_icmp;
use parquet::data_type::AsBytes;
use std::time::{SystemTime, UNIX_EPOCH};

/// Parse ICMP Time Exceeded packets (including v4/v6 headers) into a Reply result with trace information.
/// Filters out spoofed packets and only parses ICMP time exceeded valid for the current measurement.
///
/// From Wikipedia: IP header and first 64 bit of the original payload are used by the source host to match the time exceeded message to the discarded datagram.
/// For higher-level protocols such as UDP and TCP the 64-bit payload will include the source and destination ports of the discarded packet.
///
/// # Arguments
/// * `packet_bytes` - the bytes of the packet to parse (excluding the Ethernet header)
/// * `m_id` - measurement ID encoded in ICMP payload.
/// * `src` - source address of the packet (hop address)
/// * `ttl` - TTL/hop limit used when sending the original probe
/// * `origin_id` - identifier of the origin/worker that sent the probe
///
/// # Returns
/// * `Option<Reply>` - the received trace reply (None if it is not a valid ICMP Time Exceeded packet)
pub fn parse_trace(
    packet_bytes: &[u8],
    m_id: u32,
    src: Address,
    ttl: u32,
    origin_id: u32,
) -> Option<Reply> {
    // Check for ICMP Time Exceeded code
    let (min_len, type_idx, expected_type) = if src.is_v6() {
        (48, 0, 3) // IPv6: Min length 48, ICMP type at index 0, Type 3
    } else {
        (56, 20, 11) // IPv4: Min length 56, ICMP type at index 20, Type 11
    };

    if packet_bytes.len() < min_len || packet_bytes[type_idx] != expected_type {
        // Not ICMP Time exceeded; try to parse as ICMP echo reply from the target
        return parse_icmp(packet_bytes, m_id, true, src, origin_id, ttl);
    }

    let ip_header = if src.is_v6() {
        IPPacket::V6(IPv6Packet::from(packet_bytes))
    } else {
        IPPacket::V4(IPv4Packet::from(packet_bytes))
    };

    let icmp_packet = if src.is_v6() {
        ICMPPacket::from(packet_bytes) // no IP header
    } else {
        ICMPPacket::from(&packet_bytes[20..]) // skip IPv4 header
    };

    // Parse IP header that caused the Time Exceeded (first 20 bytes of the ICMP body)
    let original_ip_header = if src.is_v6() {
        IPPacket::V6(IPv6Packet::from(icmp_packet.payload.as_bytes()))
    } else {
        IPPacket::V4(IPv4Packet::from(icmp_packet.payload.as_bytes()))
    };

    // Parse the ICMP header that caused the Time Exceeded (first 8 bytes of the ICMP body after the original IP header)
    let original_icmp_header = match &original_ip_header.payload() {
        PacketPayload::Icmp { value } => value,
        _ => return None,
    };

    let seq = original_icmp_header.sequence_number;
    let id = original_icmp_header.icmp_identifier;

    // ttl (first 8 bits of seq)
    let trace_ttl = (seq >> 8) as u32;

    // get worker_id (10 bits) (lower 8 bits seq, highest 2 bits of identifier)
    let worker_lo = (seq & 0xFF) as u32;
    let worker_hi = ((id >> 14) & 0x03) as u32;
    let tx_id = (worker_hi << 8) | worker_lo;

    // get milliseconds (last 14 bits of identifier field
    let tx_time = (id & 0x3FFF) as u64;

    // get hop address
    let hop_addr = ip_header.src();

    // get trace dst address
    let trace_dst = Some(original_ip_header.dst());

    Some(Reply {
        reply_data: Some(ReplyData::Trace(TraceReply {
            hop_addr: Some(hop_addr),
            ttl: ip_header.ttl() as u32,
            origin_id,
            rx_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            tx_time,
            tx_id,
            trace_dst,
            hop_count: trace_ttl,
        })),
    })
}

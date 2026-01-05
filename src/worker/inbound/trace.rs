use crate::custom_module::manycastr::reply::ReplyData;
use crate::custom_module::manycastr::{Origin, Reply, TraceReply};
use crate::net::{IPPacket, IPv4Packet, IPv6Packet, PacketPayload};
use crate::worker::config::get_origin_id;
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
/// * `worker_map` - mapping of origin to origin ID
/// * `is_ipv6` - whether the packet is IPv6 (true) or IPv4 (false)
///
/// # Returns
/// * `Option<Reply>` - the received trace reply (None if it is not a valid ICMP Time Exceeded packet)
pub fn parse_trace(packet_bytes: &[u8], worker_map: &Vec<Origin>, is_ipv6: bool) -> Option<Reply> {
    // Check for ICMP Time Exceeded code
    // TODO handle traceroute replies from the target (will be ping echo replies rather than time exceeded)
    if is_ipv6 {
        if packet_bytes.len() < 88 {
            return None;
        }
        if packet_bytes[40] != 3 {
            return None;
        } // ICMPv6 type != Time Exceeded
    } else {
        if packet_bytes.len() < 56 {
            return None;
        }
        if packet_bytes[20] != 11 {
            return None;
        } // ICMPv4 type != Time Exceeded
    }

    let ip_header = if is_ipv6 {
        IPPacket::V6(IPv6Packet::from(packet_bytes))
    } else {
        IPPacket::V4(IPv4Packet::from(packet_bytes))
    };

    // Parse ICMP TTL Exceeded header (first 8 bytes after the IPv4 header)
    let icmp_header = match &ip_header.payload() {
        PacketPayload::Icmp { value } => value,
        _ => return None,
    };

    // Parse IP header that caused the Time Exceeded (first 20 bytes of the ICMP body)
    let original_ip_header = if is_ipv6 {
        IPPacket::V6(IPv6Packet::from(icmp_header.payload.as_bytes()))
    } else {
        IPPacket::V4(IPv4Packet::from(icmp_header.payload.as_bytes()))
    };

    // Parse the ICMP header that caused the Time Exceeded (first 8 bytes of the ICMP body after the original IP header)
    let original_icmp_header = match &original_ip_header.payload() {
        PacketPayload::Icmp { value } => value,
        _ => return None,
    };

    let seq = original_icmp_header.sequence_number;
    let id = original_icmp_header.icmp_identifier; // MUST be the identifier from the original packet!

    // ttl (first 8 bits of seq)
    let trace_ttl = (seq >> 8) as u32;

    // get worker_id (10 bits) (lower 8 bits seq, highest 2 bits of identifier)
    let worker_lo = (seq & 0xFF) as u32;
    let worker_hi = ((id >> 14) & 0x03) as u32;
    let tx_id = (worker_hi << 8) | worker_lo;

    // get milliseconds (last 14 bits of identifier field
    let tx_time = (id & 0x3FFF) as u32;

    // get hop address
    let hop_addr = ip_header.src();

    // get trace dst address
    let trace_dst = Some(original_ip_header.dst());

    // get origin ID to which this probe is targeted
    // TODO do origin_id mapping at orchestrator
    let origin_id = get_origin_id(ip_header.dst(), 0, 0, worker_map)?;

    println!(
        "received trace reply from target {}. hop {} replied with addr {}",
        original_ip_header.dst(),
        trace_ttl,
        hop_addr
    );

    Some(Reply {
        reply_data: Some(ReplyData::Trace(TraceReply {
            hop_addr: Some(hop_addr),
            ttl: ip_header.ttl() as u32,
            origin_id,
            rx_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u32,
            tx_time,
            tx_id,
            trace_dst,
            hop_count: trace_ttl,
        })),
    })
}

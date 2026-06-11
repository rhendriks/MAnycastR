use crate::custom_module::manycastr::reply::ReplyData;
use crate::custom_module::manycastr::{Address, Reply, TraceReply};
use crate::net::{ICMPPacket, IPv4Packet};
use crate::worker::inbound::ping::parse_icmp;
use crate::worker::trace_codec::TraceTag;

/// Parse ICMP Time Exceeded (and Destination Unreachable) packets into a trace Reply.
///
/// Supports traceroute probes sent via ICMP, UDP, or TCP. The original protocol is
/// detected from the IP header embedded in the Time Exceeded payload, and probe
/// identification is decoded accordingly:
///
/// - **ICMP**: identifier (worker_hi + timestamp) + sequence (TTL + worker_lo)
/// - **UDP (Paris)**: IP identification / IPv6 flow label (worker_hi + timestamp) + UDP checksum (TTL + worker_lo)
/// - **TCP**: seq number (worker_id + TTL + timestamp)
///
/// Falls back to `parse_icmp` for Echo Reply packets (destination reached in ICMP traceroute).
///
/// # Arguments
/// * `packet_bytes` - the bytes of the packet to parse (excluding the Ethernet header)
/// * `m_id` - measurement ID encoded in ICMP payload.
/// * `src` - source address of the packet (hop address)
/// * `ttl` - TTL/hop limit of the received packet
/// * `rx_time` - kernel receive timestamp in microseconds
///
/// # Returns
/// * `Option<Reply>` - the received trace reply (None if not a valid trace response)
pub fn parse_trace(
    packet_bytes: &[u8],
    m_id: u32,
    src: Address,
    ttl: u32,
    rx_time: u64,
) -> Option<Reply> {
    let is_v6 = src.is_v6();

    // ICMP error type numbers, and where the ICMP header starts
    let (time_exceeded, dest_unreachable, icmp_start) = if is_v6 {
        (3u8, 1u8, 0usize)
    } else {
        (11u8, 3u8, 20usize)
    };

    // Only Time Exceeded / Destination Unreachable quote the original probe
    match packet_bytes.get(icmp_start) {
        Some(&t) if t == time_exceeded || t == dest_unreachable => {}
        _ => return parse_icmp(packet_bytes, m_id, true, src, ttl, false, rx_time),
    }

    // Hop address + TTL of the outer error packet.
    let (hop_addr, hop_ttl) = if is_v6 {
        (src, ttl)
    } else {
        let ip = IPv4Packet::from(packet_bytes);
        (Address::from(ip.src), ip.ttl as u32)
    };

    // Need the full 8-byte ICMP header before parsing it (the parser unwraps those bytes).
    if packet_bytes.len() < icmp_start + 8 {
        return parse_icmp(packet_bytes, m_id, true, src, ttl, false, rx_time);
    }

    // The ICMP payload is the quoted original probe (its IP header + first 8 transport bytes).
    let icmp = ICMPPacket::from(&packet_bytes[icmp_start..]);
    let quoted = parse_quoted_probe(&icmp.payload, is_v6)?;

    // Recover the probe identity from the protocol-specific carrier fields (layouts in trace_codec).
    let t = quoted.transport;
    let tag = match quoted.protocol {
        // ICMP (1) / ICMPv6 (58): identifier + sequence number
        1 | 58 => TraceTag::decode_split(
            u16::from_be_bytes([t[4], t[5]]),
            u16::from_be_bytes([t[6], t[7]]),
        ),
        // UDP (17): id field (IPv4 identification / IPv6 flow label) + UDP checksum
        17 => TraceTag::decode_split(quoted.id_field, u16::from_be_bytes([t[6], t[7]])),
        // TCP (6): whole identity in the 32-bit sequence number
        6 => TraceTag::decode_tcp_seq(u32::from_be_bytes([t[4], t[5], t[6], t[7]])),
        _ => return None,
    };

    Some(make_trace_reply(
        hop_addr,
        hop_ttl,
        rx_time,
        tag.ts14 as u64,
        tag.worker_id,
        quoted.dst,
        tag.ttl as u32,
    ))
}

/// Fields recovered from the original (quoted) probe inside an ICMP error message.
struct QuotedProbe<'a> {
    /// IP protocol number of the quoted probe (1/58 ICMP, 17 UDP, 6 TCP).
    protocol: u8,
    /// Destination address of the quoted probe (the trace target).
    dst: Address,
    /// Codec id field: IPv4 Identification, or the low 16 bits of the IPv6 flow label.
    id_field: u16,
    /// The quoted transport header — guaranteed to be at least 8 bytes.
    transport: &'a [u8],
}

/// Parse the quoted IP datagram carried in an ICMP error message.
fn parse_quoted_probe(payload: &[u8], is_v6: bool) -> Option<QuotedProbe<'_>> {
    if is_v6 {
        // IPv6 header is a fixed 40 bytes; need 8 transport bytes after it.
        if payload.len() < 48 {
            return None;
        }
        let id_field = (u32::from_be_bytes(payload[0..4].try_into().ok()?) & 0x000F_FFFF) as u16;
        Some(QuotedProbe {
            protocol: payload[6], // Next Header
            dst: Address::from(u128::from_be_bytes(payload[24..40].try_into().ok()?)),
            id_field,
            transport: &payload[40..],
        })
    } else {
        let ihl = ((*payload.first()? & 0x0F) as usize) * 4;
        let transport = payload.get(ihl..)?;
        if transport.len() < 8 {
            return None;
        }
        Some(QuotedProbe {
            protocol: *payload.get(9)?, // Protocol
            dst: Address::from(u32::from_be_bytes(payload.get(16..20)?.try_into().ok()?)),
            id_field: u16::from_be_bytes([*payload.get(4)?, *payload.get(5)?]), // IP Identification
            transport,
        })
    }
}

/// Helper to construct a trace Reply from decoded fields
fn make_trace_reply(
    hop_addr: Address,
    ttl: u32,
    rx_time: u64,
    tx_time: u64,
    tx_id: u32,
    trace_dst: Address,
    hop_count: u32,
) -> Reply {
    Reply {
        reply_data: Some(ReplyData::Trace(TraceReply {
            hop_addr: Some(hop_addr),
            ttl,
            rtt: super::rtt_ms(rx_time, tx_time, super::TxEncoding::Trace14),
            tx_id,
            trace_dst: Some(trace_dst),
            hop_count,
        })),
    }
}

use crate::custom_module::manycastr::reply::ReplyData;
use crate::custom_module::manycastr::{Address, Reply, TraceReply};
use crate::net::{ICMPPacket, IPv4Packet};
use crate::worker::inbound::ping::parse_icmp;

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

    // Determine ICMP type offsets and expected types
    let (min_len, type_idx, time_exceeded, dest_unreachable) = if is_v6 {
        (48usize, 0usize, 3u8, 1u8) // ICMPv6
    } else {
        (56, 20, 11, 3) // ICMPv4
    };

    if packet_bytes.len() < min_len {
        return parse_icmp(packet_bytes, m_id, true, src, ttl, false, rx_time);
    }

    let icmp_type = packet_bytes[type_idx];
    if icmp_type != time_exceeded && icmp_type != dest_unreachable {
        // Not Time Exceeded or Destination Unreachable — try as Echo Reply (ICMP traceroute target)
        return parse_icmp(packet_bytes, m_id, true, src, ttl, false, rx_time);
    }

    // Extract hop address and TTL from the outer packet
    let (hop_addr, hop_ttl) = if is_v6 {
        (src, ttl)
    } else {
        let ip_header = IPv4Packet::from(packet_bytes);
        (Address::from(ip_header.src), ip_header.ttl as u32)
    };

    // Parse the outer ICMP packet to access its payload (the original packet)
    let icmp_packet = if is_v6 {
        ICMPPacket::from(packet_bytes)
    } else {
        ICMPPacket::from(&packet_bytes[20..])
    };

    let payload = &icmp_packet.payload;

    // Determine original IP header fields and transport data offset
    let (original_protocol, original_dst, ip_identification, flow_label, transport_offset) =
        if is_v6 {
            // IPv6 header: 40 bytes minimum
            if payload.len() < 48 {
                return None;
            }
            let next_header = payload[6];
            let dst = u128::from_be_bytes(payload[24..40].try_into().ok()?);
            let flow_bytes = u32::from_be_bytes(payload[0..4].try_into().ok()?);
            let fl = flow_bytes & 0x000F_FFFF;
            (next_header, Address::from(dst), 0u16, fl, 40usize)
        } else {
            // IPv4 header: variable length (IHL field)
            if payload.len() < 28 {
                return None;
            }
            let ihl = ((payload[0] & 0x0F) as usize) * 4;
            let protocol = payload[9];
            // IP Identification is at bytes 4-5 of the IPv4 header
            let ip_id = u16::from_be_bytes([payload[4], payload[5]]);
            let dst = u32::from_be_bytes(payload[16..20].try_into().ok()?);
            (protocol, Address::from(dst), ip_id, 0u32, ihl)
        };

    // Ensure we have at least 8 bytes of transport data
    if payload.len() < transport_offset + 8 {
        return None;
    }
    let transport = &payload[transport_offset..];

    match original_protocol {
        // ICMP (1) or ICMPv6 (58): existing encoding in identifier + sequence number
        1 | 58 => {
            let id = u16::from_be_bytes([transport[4], transport[5]]);
            let seq = u16::from_be_bytes([transport[6], transport[7]]);

            let trace_ttl = (seq >> 8) as u32;
            let worker_lo = (seq & 0xFF) as u32;
            let worker_hi = ((id >> 14) & 0x03) as u32;
            let tx_id = (worker_hi << 8) | worker_lo;
            let tx_time = (id & 0x3FFF) as u64;

            Some(make_trace_reply(
                hop_addr,
                hop_ttl,
                rx_time,
                tx_time,
                tx_id,
                original_dst,
                trace_ttl,
            ))
        }

        // UDP (17): Paris encoding in IP identification/flow label + UDP checksum
        17 => {
            let checksum = u16::from_be_bytes([transport[6], transport[7]]);

            let trace_ttl = (checksum >> 8) as u32;
            let worker_lo = (checksum & 0xFF) as u32;

            // Worker high bits + timestamp from IP identification (v4) or flow label (v6)
            let encoded = if is_v6 {
                flow_label as u16
            } else {
                ip_identification
            };
            let worker_hi = ((encoded >> 14) & 0x03) as u32;
            let tx_time = (encoded & 0x3FFF) as u64;

            let tx_id = (worker_hi << 8) | worker_lo;

            Some(make_trace_reply(
                hop_addr,
                hop_ttl,
                rx_time,
                tx_time,
                tx_id,
                original_dst,
                trace_ttl,
            ))
        }

        // TCP (6): all encoded in the TCP sequence number (32 bits)
        6 => {
            let seq = u32::from_be_bytes([transport[4], transport[5], transport[6], transport[7]]);

            let tx_id = (seq >> 22) & 0x3FF;
            let trace_ttl = ((seq >> 14) & 0xFF) as u32;
            let tx_time = (seq & 0x3FFF) as u64;

            Some(make_trace_reply(
                hop_addr,
                hop_ttl,
                rx_time,
                tx_time,
                tx_id,
                original_dst,
                trace_ttl,
            ))
        }

        _ => None,
    }
}

/// Helper to construct a trace Reply from decoded fields.
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
            rx_time,
            tx_time,
            tx_id,
            trace_dst: Some(trace_dst),
            hop_count,
        })),
    }
}

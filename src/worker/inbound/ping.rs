use crate::custom_module::manycastr::reply::ReplyData;
use crate::custom_module::manycastr::{
    Address, DiscoveryReply, MeasurementReply, RecordedHops, Reply, TraceReply,
};
use crate::net::ICMPPacket;
use crate::worker::inbound::ReplyMeta;

/// Parse ICMP ping packets into a Reply result.
/// Filters out spoofed packets and only parses ICMP echo replies valid for the current measurement.
///
/// # Arguments
/// * `packet_bytes` - the bytes of the packet to parse
/// * `m_id` - the ID of the current measurement
/// * `is_traceroute` - handle echo reply as traceroute target reply
/// * `is_dgram` - whether the socket is DGRAM (if true, the kernel strips the IPv4 header)
/// * `meta` - received packet metadata (source address, TTL, kernel receive time)
///
/// # Returns
/// * `Option<Reply>` - the received ping reply, None if invalid
///
/// # Remarks
/// The function returns None if the packet is not an ICMP echo reply or if the packet is too short to contain the necessary information.
pub fn parse_icmp(
    packet_bytes: &[u8],
    m_id: u32,
    is_traceroute: bool,
    is_dgram: bool,
    meta: ReplyMeta,
) -> Option<Reply> {
    if meta.src.is_v6() {
        // ICMPv6: no IP header in received data (both RAW and DGRAM)
        if packet_bytes.len() < 56 || packet_bytes[0] != 129 {
            return None;
        }
        let icmp_packet = ICMPPacket::from(packet_bytes);
        parse_icmp_inner(&icmp_packet, m_id, None, is_traceroute, meta)
    } else if is_dgram {
        // DGRAM: kernel strips IPv4 header, ICMP data starts at offset 0
        if packet_bytes.len() < 32 || packet_bytes[0] != 0 {
            return None;
        }
        let icmp_packet = ICMPPacket::from(packet_bytes);
        parse_icmp_inner(&icmp_packet, m_id, None, is_traceroute, meta)
    } else {
        // RAW: IPv4 header included, ICMP starts at offset 20
        if packet_bytes.len() < 52 || packet_bytes[20] != 0 {
            return None;
        }
        let icmp_packet = ICMPPacket::from(&packet_bytes[20..]);
        parse_icmp_inner(&icmp_packet, m_id, None, is_traceroute, meta)
    }
}

/// Parse ICMP ping packets into a Reply result (excluding the IP header).
///
/// # Arguments
/// * `icmp_packet` - Unparsed ICMP packet
/// * `m_id` - the ID of the current measurement
/// * `recorded_hops` - optional recorded hops from the IP header when Record Route (RR) is used
/// * `is_traceroute` - whether this is a traceroute target ping reply
/// * `meta` - received packet metadata (source address, TTL, kernel receive time)
///
/// # Returns
/// * `Option<Reply>` - the received ping reply, None if invalid
pub fn parse_icmp_inner(
    icmp_packet: &ICMPPacket,
    m_id: u32,
    recorded_hops: Option<RecordedHops>,
    is_traceroute: bool,
    meta: ReplyMeta,
) -> Option<Reply> {
    let ReplyMeta { src, ttl, rx_time } = meta;
    // Make sure that this packet belongs to this measurement
    let pkt_measurement_id: [u8; 4] = icmp_packet.payload[0..4].try_into().ok()?;
    if u32::from_be_bytes(pkt_measurement_id) != m_id {
        return None;
    }

    let is_ipv6 = src.is_v6();

    let tx_time = u64::from_be_bytes(icmp_packet.payload[4..12].try_into().unwrap());
    let mut tx_id = u32::from_be_bytes(icmp_packet.payload[12..16].try_into().unwrap());
    let probe_dst = if is_ipv6 {
        Address::from(u128::from_be_bytes(
            icmp_packet.payload[32..48].try_into().unwrap(),
        ))
    } else {
        Address::from(u32::from_be_bytes(
            icmp_packet.payload[20..24].try_into().unwrap(),
        ))
    };

    if probe_dst != src {
        return None; // spoofed reply
    }

    let is_discovery = if tx_id > u16::MAX as u32 {
        tx_id -= u16::MAX as u32;
        true
    } else {
        false
    };

    if is_discovery {
        // Discovery reply
        Some(Reply {
            reply_data: Some(ReplyData::Discovery(DiscoveryReply { src: Some(src) })),
        })
    } else if is_traceroute {
        // Trace reply
        let trace_ttl: u8 = if is_ipv6 {
            icmp_packet.payload[48]
        } else {
            icmp_packet.payload[24]
        };

        Some(Reply {
            reply_data: Some(ReplyData::Trace(TraceReply {
                hop_addr: Some(src),
                ttl,
                rtt: super::rtt_ms(rx_time, tx_time, super::TxEncoding::Micros),
                tx_id,
                trace_dst: Some(src),
                hop_count: trace_ttl as u32,
            })),
        })
    } else {
        // Ping reply
        Some(Reply {
            reply_data: Some(ReplyData::Measurement(MeasurementReply {
                src: Some(src),
                ttl,
                rtt: super::rtt_ms(rx_time, tx_time, super::TxEncoding::Micros),
                tx_id,
                chaos: None,
                recorded_hops,
            })),
        })
    }
}

use crate::custom_module::manycastr::reply::ReplyData;
use crate::custom_module::manycastr::{
    Address, DiscoveryReply, MeasurementReply, Origin, RecordedHops, Reply, TraceReply,
};
use crate::net::{ICMPPacket, IPPacket, IPv4Packet, IPv6Packet, PacketPayload};
use crate::worker::config::get_origin_id;
use std::time::{SystemTime, UNIX_EPOCH};

/// Parse ICMP ping packets into a Reply result.
/// Filters out spoofed packets and only parses ICMP echo replies valid for the current measurement.
///
/// # Arguments
/// * `packet_bytes` - the bytes of the packet to parse
/// * `m_id` - the ID of the current measurement
/// * `origin_map` - mapping of origin to origin ID
/// * `is_ipv6` - whether the packet is IPv6 (true) or IPv4 (false)
/// * `is_traceroute` - handle echo reply as traceroute target reply
///
/// # Returns
/// * `Option<Reply>` - the received ping reply, None if invalid
///
/// # Remarks
/// The function returns None if the packet is not an ICMP echo reply or if the packet is too short to contain the necessary information.
pub fn parse_icmp(
    packet_bytes: &[u8],
    m_id: u32,
    origin_map: &[Origin],
    is_ipv6: bool,
    is_traceroute: bool,
) -> Option<Reply> {
    // ICMPv6 66 length (IPv6 header (40) + ICMP header (8) + ICMP body 48 bytes) + check it is an ICMP Echo reply
    if (is_ipv6 && (packet_bytes.len() < 66 || packet_bytes[40] != 129))
        || (!is_ipv6 && (packet_bytes.len() < 52 || packet_bytes[20] != 0))
    {
        return None;
    }

    let ip_header = if is_ipv6 {
        IPPacket::V6(IPv6Packet::from(packet_bytes))
    } else {
        IPPacket::V4(IPv4Packet::from(packet_bytes))
    };

    let PacketPayload::Icmp { value: icmp_packet } = ip_header.payload() else {
        return None;
    };

    parse_icmp_inner(
        icmp_packet,
        &ip_header,
        m_id,
        origin_map,
        is_ipv6,
        None,
        is_traceroute,
    )
}

/// Parse ICMP ping packets into a Reply result (excluding the IP header).
///
/// # Arguments
/// * `icmp_packet` - Unparsed ICMP packet
/// * `ip_header` - Parsed IP header
/// * `m_id` - the ID of the current measurement
/// * `origin_map` - mapping of origin to origin ID
/// * `is_ipv6` - whether the packet is IPv6 (true) or IPv4 (false)
/// * `recorded_hops` - optional recorded hops from the IP header when Record Route (RR) is used
/// * `is_traceroute` - handle echo reply as traceroute target reply
///
/// # Returns
/// * `Option<Reply>` - the received ping reply, None if invalid
pub fn parse_icmp_inner(
    icmp_packet: &ICMPPacket,
    ip_header: &IPPacket,
    m_id: u32,
    origin_map: &[Origin],
    is_ipv6: bool,
    recorded_hops: Option<RecordedHops>,
    is_traceroute: bool,
) -> Option<Reply> {
    // Make sure that this packet belongs to this measurement
    let pkt_measurement_id: [u8; 4] = icmp_packet.payload[0..4].try_into().ok()?;
    if u32::from_be_bytes(pkt_measurement_id) != m_id {
        return None;
    }

    let tx_time = u64::from_be_bytes(icmp_packet.payload[4..12].try_into().unwrap());
    let mut tx_id = u32::from_be_bytes(icmp_packet.payload[12..16].try_into().unwrap());
    let (probe_src, probe_dst) = if is_ipv6 {
        (
            Address::from(u128::from_be_bytes(
                icmp_packet.payload[16..32].try_into().unwrap(),
            )),
            Address::from(u128::from_be_bytes(
                icmp_packet.payload[32..48].try_into().unwrap(),
            )),
        )
    } else {
        (
            Address::from(u32::from_be_bytes(
                icmp_packet.payload[16..20].try_into().unwrap(),
            )),
            Address::from(u32::from_be_bytes(
                icmp_packet.payload[20..24].try_into().unwrap(),
            )),
        )
    };

    if (probe_src != ip_header.dst()) | (probe_dst != ip_header.src()) {
        return None; // spoofed reply
    }

    let origin_id = get_origin_id(ip_header.dst(), 0, 0, origin_map)?;

    let rx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;

    let is_discovery = if tx_id > u16::MAX as u32 {
        tx_id -= u16::MAX as u32;
        true
    } else {
        false
    };

    if is_discovery {
        Some(Reply {
            reply_data: Some(ReplyData::Discovery(DiscoveryReply {
                src: Some(ip_header.src()),
                origin_id,
            })),
        })
    } else if is_traceroute {
        let trace_ttl: u8 = if is_ipv6 {
            icmp_packet.payload[49]
        } else {
            icmp_packet.payload[25]
        };

        Some(Reply {
            reply_data: Some(ReplyData::Trace(TraceReply {
                hop_addr: Some(ip_header.src()),
                ttl: ip_header.ttl() as u32,
                origin_id,
                rx_time,
                tx_time,
                tx_id,
                trace_dst: Some(ip_header.src()),
                hop_count: trace_ttl as u32,
            })),
        })
    } else {
        Some(Reply {
            reply_data: Some(ReplyData::Measurement(MeasurementReply {
                src: Some(ip_header.src()),
                ttl: ip_header.ttl() as u32,
                origin_id,
                rx_time,
                tx_time,
                tx_id,
                chaos: None,
                recorded_hops,
            })),
        })
    }
}

use crate::custom_module::manycastr::result::ResultData;
use crate::custom_module::manycastr::{Address, Origin, ProbeDiscovery, ProbeMeasurement, Result};
use crate::net::{IPPacket, IPv4Packet, IPv6Packet, PacketPayload};
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
///
/// # Returns
/// * `Option<(Reply, bool)>` - the received ping reply and whether it is a discovery packet
///
/// # Remarks
/// The function returns None if the packet is not an ICMP echo reply or if the packet is too short to contain the necessary information.
pub fn parse_icmp(
    packet_bytes: &[u8],
    m_id: u32,
    origin_map: &Vec<Origin>,
    is_ipv6: bool,
) -> Option<Result> {
    // ICMPv6 66 length (IPv6 header (40) + ICMP header (8) + ICMP body 48 bytes) + check it is an ICMP Echo reply TODO match with exact length (include -u URl length)
    // ICMPv4 52 length (IPv4 header (20) + ICMP header (8) + ICMP body 24 bytes) + check it is an ICMP Echo reply TODO match with exact length (include -u URl length)
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

    // Make sure that this packet belongs to this measurement
    let pkt_measurement_id: [u8; 4] = icmp_packet.payload[0..4].try_into().ok()?; // TODO move to initial if statement
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
        Some(Result {
            result_data: Some(ResultData::Discovery(ProbeDiscovery {
                src: Some(ip_header.src()),
                origin_id,
            })),
        })
    } else {
        Some(Result {
            result_data: Some(ResultData::Measurement(ProbeMeasurement {
                src: Some(ip_header.src()),
                ttl: ip_header.ttl() as u32,
                origin_id,
                rx_time,
                tx_time, // Ensure this uses your calculated 21-bit logic if TCP
                tx_id,
                chaos: None,
                recorded_hops: None,
            })),
        })
    }
}

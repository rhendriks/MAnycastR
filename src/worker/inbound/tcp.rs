use std::time::{SystemTime, UNIX_EPOCH};
use crate::custom_module::manycastr::{Origin, ProbeDiscovery, ProbeMeasurement, Result};
use crate::custom_module::manycastr::result::ResultData;
use crate::net::{IPPacket, IPv4Packet, IPv6Packet, PacketPayload};
use crate::worker::config::get_origin_id;

/// Parse TCP packets into a Reply result.
/// Only accepts packets with the RST flag set.
///
/// # Arguments
/// * `packet_bytes` - the bytes of the packet to parse
/// * `origin_map` - mapping of origin to origin ID
/// * `is_ipv6` - whether to parse the packet as IPv6 or IPv4
///
/// # Returns
/// * `Option<ResultData>` - the received TCP reply
///
/// # Remarks
/// The function returns None if the packet is too short to contain a TCP header or if the RST flag is not set.
pub fn parse_tcp(
    packet_bytes: &[u8],
    origin_map: &Vec<Origin>,
    is_ipv6: bool,
) -> Option<Result> {
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
    );

    let identifier = tcp_packet.seq.wrapping_sub(1); // seq = ack + 1
    let is_discovery = (identifier >> 31) & 1 == 1;
    let tx_id = (identifier >> 21) & 0x3FF;
    let tx_time_21b = identifier & 0x1FFFFF;

    if is_discovery {
        Some(Result {
            result_data:         Some(ResultData::Discovery(ProbeDiscovery {
                src: Some(ip_header.src()),
                origin_id,
            }
            ))
        })
    } else {
        Some(Result {
            result_data: Some(ResultData::Measurement(ProbeMeasurement {
                src: Some(ip_header.src()),
                ttl: ip_header.ttl() as u32,
                origin_id,
                rx_time,
                tx_time: tx_time_21b as u64,
                tx_id,
                chaos: None,
                recorded_hops: None,
            }))
        })
    }
}

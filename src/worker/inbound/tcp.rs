use crate::custom_module::manycastr::reply::ReplyData;
use crate::custom_module::manycastr::{Address, DiscoveryReply, MeasurementReply, Reply};
use crate::net::{IPPacket, IPv4Packet, IPv6Packet, TCPPacket};
use std::time::{SystemTime, UNIX_EPOCH};

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
pub fn parse_tcp(packet_bytes: &[u8], origin_id: u32, is_ipv6: bool, src: Address, ttl: u32) -> Option<Reply> {
    // Verify RST flag is set
    if (is_ipv6 && (packet_bytes[13] & 0x04) == 0)
        || (!is_ipv6 && (packet_bytes[33] & 0x04) == 0)
    {
        return None;
    }
    
    let tcp_packet = if is_ipv6{
        TCPPacket::from(packet_bytes)
    } else {
        TCPPacket::from(&packet_bytes[20..])
    };

    let rx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;

    let identifier = tcp_packet.seq.wrapping_sub(1); // seq = ack + 1
    let is_discovery = (identifier >> 31) & 1 == 1;
    let tx_id = (identifier >> 21) & 0x3FF;
    let tx_time_21b = identifier & 0x1FFFFF;

    if is_discovery {
        Some(Reply {
            reply_data: Some(ReplyData::Discovery(DiscoveryReply {
                src: Some(src),
                origin_id,
            })),
        })
    } else {
        Some(Reply {
            reply_data: Some(ReplyData::Measurement(MeasurementReply {
                src: Some(src),
                ttl,
                origin_id,
                rx_time,
                tx_time: tx_time_21b as u64,
                tx_id,
                chaos: None,
                recorded_hops: None,
            })),
        })
    }
}

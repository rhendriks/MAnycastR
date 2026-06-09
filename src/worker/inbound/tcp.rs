use crate::custom_module::manycastr::reply::ReplyData;
use crate::custom_module::manycastr::{Address, DiscoveryReply, MeasurementReply, Reply, TraceReply};
use crate::net::TCPPacket;
use crate::worker::trace_codec::TraceTag;

/// Parse TCP packets into a Reply result.
/// Only accepts packets with the RST flag set.
///
/// # Arguments
/// * `packet_bytes` - the bytes of the packet to parse
/// * `src` - source address of the received packet
/// * `ttl` - TTL of the received packet
/// * `sport` - Source port used for outgoing packets (destination port of replies)
/// * `rx_time` - kernel receive timestamp in microseconds
/// * `is_traceroute` - If true, check for traceroute destination replies
///
/// # Returns
/// * `Option<ResultData>` - the received TCP reply
///
/// # Remarks
/// The function returns None if the packet is too short to contain a TCP header or if the RST flag is not set.
pub fn parse_tcp(
    packet_bytes: &[u8],
    src: Address,
    ttl: u32,
    sport: u16,
    rx_time: u64,
    is_traceroute: bool,
) -> Option<Reply> {
    // Verify RST flag is set
    if (src.is_v6() && (packet_bytes[13] & 0x04) == 0)
        || (!src.is_v6() && (packet_bytes[33] & 0x04) == 0)
    {
        return None;
    }

    let tcp_packet = if src.is_v6() {
        TCPPacket::from(packet_bytes)
    } else {
        TCPPacket::from(&packet_bytes[20..])
    };

    // Verify destination port matches our source port
    if tcp_packet.dport != sport {
        return None;
    }

    let identifier = tcp_packet.seq.wrapping_sub(1); // RST.seq = our ack + 1
    let is_discovery = (identifier >> 31) & 1 == 1;

    if is_discovery {
        // Discovery probe (regular layout sets bit 31); identifies the catching worker.
        Some(Reply {
            reply_data: Some(ReplyData::Discovery(DiscoveryReply { src: Some(src) })),
        })
    } else if is_traceroute {
        // Probe reply to a traceroute packet
        let tag = TraceTag::decode_tcp_seq(identifier);
        Some(Reply {
            reply_data: Some(ReplyData::Trace(TraceReply {
                hop_addr: Some(src),
                ttl,
                rx_time,
                tx_time: tag.ts14 as u64,
                tx_id: tag.worker_id,
                trace_dst: Some(src),
                hop_count: tag.ttl as u32,
            })),
        })
    } else {
        let tx_id = (identifier >> 21) & 0x3FF;
        let tx_time_21b = identifier & 0x1FFFFF;
        Some(Reply {
            reply_data: Some(ReplyData::Measurement(MeasurementReply {
                src: Some(src),
                ttl,
                rx_time,
                tx_time: tx_time_21b as u64,
                tx_id,
                chaos: None,
                recorded_hops: None,
            })),
        })
    }
}

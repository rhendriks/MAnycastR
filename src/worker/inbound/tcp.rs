use crate::custom_module::manycastr::reply::ReplyData;
use crate::custom_module::manycastr::{DiscoveryReply, MeasurementReply, Reply, TraceReply};
use crate::net::TCPPacket;
use crate::worker::inbound::ReplyMeta;
use crate::worker::trace_codec::TraceTag;

/// Parse TCP packets into a Reply result.
/// Only accepts packets with the RST flag set.
///
/// # Arguments
/// * `packet_bytes` - the bytes of the packet to parse
/// * `sport` - Source port used for outgoing packets (destination port of replies)
/// * `is_traceroute` - If true, check for traceroute destination replies
/// * `meta` - received packet metadata (source address, TTL, kernel receive time)
///
/// # Returns
/// * `Option<ResultData>` - the received TCP reply
///
/// # Remarks
/// The function returns None if the packet is too short to contain a TCP header or if the RST flag is not set.
pub fn parse_tcp(
    packet_bytes: &[u8],
    sport: u16,
    is_traceroute: bool,
    meta: ReplyMeta,
) -> Option<Reply> {
    let ReplyMeta { src, ttl, rx_time } = meta;
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
        // Trace probe
        let tag = TraceTag::decode_tcp_seq(identifier);
        Some(Reply {
            reply_data: Some(ReplyData::Trace(TraceReply {
                hop_addr: Some(src),
                ttl,
                rtt: super::rtt_ms(rx_time, tag.ts14 as u64, super::TxEncoding::Trace14),
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
                rtt: super::rtt_ms(rx_time, tx_time_21b as u64, super::TxEncoding::Tcp21),
                tx_id,
                chaos: None,
            })),
        })
    }
}

use crate::custom_module::manycastr::{ProtocolType, Trace};
use crate::net::packet::{
    ProbePayload, TraceDnsId, create_icmp, create_tcp_trace, create_udp_trace,
};
use crate::worker::outbound::{OutboundConfig, send_packet};
use crate::worker::trace_codec::TraceTag;
use log::warn;
use socket2::Socket;
use std::time::{SystemTime, UNIX_EPOCH};

/// Sends a traceroute probe based on the provided trace task, protocol, and configuration.
///
/// Supports ICMP, UDP (Paris), and TCP (Paris) traceroute.
///
/// - **ICMP**: identifier (worker_hi + timestamp) + sequence (TTL + worker_lo)
/// - **UDP (Paris)**: IP identification/flow label (worker_hi + timestamp) + UDP checksum (TTL + worker_lo)
/// - **TCP (Paris)**: seq number (worker_id + TTL + timestamp)
///
/// # Arguments
/// * `config` - The outbound configuration (worker, measurement, origin, and protocol details).
/// * `trace_task` - The traceroute task containing destination and TTL information.
/// * `socket` - The socket to send the packet on.
pub fn send_trace(config: &OutboundConfig, trace_task: &Trace, socket: &Socket) -> (u32, u32) {
    let worker_id = config.worker_id as u32;
    let p_type = config.p_type;
    let src = &config.src;
    let info_url = config.info_url.as_deref();
    let target = &trace_task.dst.unwrap();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let tx_micros = now.as_micros() as u64;
    let tag = TraceTag {
        worker_id,
        ttl: trace_task.ttl as u8,
        ts14: (now.as_millis() & 0x3FFF) as u16,
    };
    let ttl = tag.ttl;

    let packet = match p_type {
        ProtocolType::Icmp => {
            // ICMP: encode in identifier + sequence number
            let (identifier, sequence_number) = tag.encode_split();

            let payload_fields = ProbePayload {
                worker_id,
                m_id: config.m_id,
                trace_ttl: Some(ttl),
                info_url,
            };

            create_icmp(
                src,
                target,
                identifier,
                sequence_number,
                &payload_fields,
                ttl,
                false, // traceroute always uses raw sockets
            )
        }

        ProtocolType::ADns | ProtocolType::ChaosDns => {
            // UDP (Paris): IP identification/flow label + UDP checksum carry the identity.
            let (identifier, desired_checksum) = tag.encode_split();

            create_udp_trace(
                src,
                target,
                config.sport,
                config.dport,
                identifier,
                desired_checksum,
                &TraceDnsId {
                    tx_id: worker_id,
                    m_id: config.m_id,
                    tx_micros,
                    ttl,
                    qname: config.qname.as_deref().unwrap_or("example.org"),
                },
            )
        }

        ProtocolType::Tcp => {
            // TCP (Paris): the whole identity is packed into the 32-bit sequence number.
            let seq = tag.encode_tcp_seq();

            create_tcp_trace(src, target, config.sport, config.dport, seq, ttl, info_url)
        }
    };

    // For ICMP on IPv6, the kernel writes the header, so we set hop limit via socket option.
    // For UDP/TCP on IPv6, we include the IPv6 header (header_included_v6), so TTL is in the packet.
    // TODO header included does not work for IPv6?
    if src.is_v6()
        && p_type == ProtocolType::Icmp
        && let Err(e) = socket.set_unicast_hops_v6(trace_task.ttl)
    {
        warn!(
            "[Worker outbound] Failed to set IPv6 hop limit to {}: {e}",
            trace_task.ttl
        );
    }

    let result = match send_packet(
        socket,
        &packet,
        &trace_task.dst.expect("invalid destination"),
        0,
    ) {
        Ok(()) => (1, 0),
        Err(e) => {
            warn!("[Worker outbound] Failed to send {p_type} traceroute packet: {e}");
            (0, 1)
        }
    };

    // Restore the default hop limit for ICMP IPv6
    if src.is_v6() && p_type == ProtocolType::Icmp {
        let _ = socket.set_unicast_hops_v6(255);
    }

    result
}

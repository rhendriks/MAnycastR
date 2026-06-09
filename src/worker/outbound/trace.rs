use crate::custom_module::manycastr::{Address, ProtocolType, Trace};
use crate::net::packet::{create_icmp, create_tcp_trace, create_udp_trace, ProbePayload};
use crate::worker::outbound::send_packet;
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
/// * `worker_id` - This worker's identifier.
/// * `m_id` - Unique measurement ID.
/// * `info_url` - Optional URL encoded in the payload.
/// * `trace_task` - The traceroute task containing destination and TTL information.
/// * `socket` - The socket to send the packet on.
/// * `src` - Source address bound to this socket.
/// * `p_type` - Protocol type to use for the probe.
/// * `sport` - Configured source port (for UDP/TCP, constant across probes).
/// * `dport` - Configured destination port (for UDP/TCP, constant across probes).
pub fn send_trace(
    worker_id: u32,
    m_id: u32,
    info_url: Option<&str>,
    trace_task: &Trace,
    socket: &Socket,
    src: &Address,
    p_type: ProtocolType,
    sport: u16,
    dport: u16,
) -> (u32, u32) {
    let target = &trace_task.dst.unwrap();

    // Store 14 bits of millisecond timestamp
    let tx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let timestamp_14b = (tx_time & 0x3FFF) as u16;

    // Store worker_id as 10-bit number (up to 1,024 workers)
    let worker_lo_8 = (worker_id & 0xFF) as u16;
    let worker_hi_2 = ((worker_id >> 8) & 0x03) as u16;

    let ttl = trace_task.ttl as u8;

    let packet = match p_type {
        ProtocolType::Icmp => {
            // ICMP: encode in identifier + sequence number
            let sequence_number: u16 = ((trace_task.ttl as u16) << 8) | worker_lo_8;
            let identifier: u16 = (worker_hi_2 << 14) | timestamp_14b;

            let payload_fields = ProbePayload {
                worker_id,
                m_id,
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
            // UDP Paris traceroute: keep ports fixed, encode in IP identification + UDP checksum
            let identifier: u16 = (worker_hi_2 << 14) | timestamp_14b;
            let desired_checksum: u16 = ((trace_task.ttl as u16) << 8) | worker_lo_8;

            create_udp_trace(
                src,
                target,
                sport,
                dport,
                identifier,
                desired_checksum,
                ttl,
                m_id,
                info_url,
            )
        }

        ProtocolType::Tcp => {
            // TCP traceroute: encode all in TCP sequence number (32 bits)
            let worker_10b = worker_id & 0x3FF;
            let seq = (worker_10b << 22) | ((trace_task.ttl & 0xFF) << 14) | (timestamp_14b as u32);

            create_tcp_trace(src, target, sport, dport, seq, ttl, info_url)
        }
    };

    // DEBUG: decode the L4 destination port actually present in the crafted trace packet.
    eprintln!(
        "[send_trace DEBUG] p_type={p_type:?} ttl={} sport={sport} config.dport={dport} pkt_len={} l4_dport_in_pkt={:?} target={target}",
        trace_task.ttl,
        packet.len(),
        crate::worker::outbound::probe::l4_dport_from_packet(target, false, &packet),
    );

    // For ICMP on IPv6, the kernel writes the header, so we set hop limit via socket option.
    // For UDP/TCP on IPv6, we include the IPv6 header (header_included_v6), so TTL is in the packet.
    // TODO header included does not work for IPv6?
    if src.is_v6() && p_type == ProtocolType::Icmp {
        if let Err(e) = socket.set_unicast_hops_v6(trace_task.ttl) {
            warn!(
                "[Worker outbound] Failed to set IPv6 hop limit to {}: {e}",
                trace_task.ttl
            );
        }
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

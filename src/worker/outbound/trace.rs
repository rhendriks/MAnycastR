use crate::custom_module::manycastr::{Address, Trace};
use crate::net::packet::{create_icmp, ProbePayload};
use crate::worker::outbound::send_packet;
use log::warn;
use socket2::Socket;
use std::time::{SystemTime, UNIX_EPOCH};

/// Sends a traceroute probe based on the provided trace task and configuration.
/// Only ICMP traceroute is currently implemented.
/// # Arguments
/// * `worker_id` - This worker's identifier.
/// * `m_id` - Unique measurement ID.
/// * `info_url` - Optional URL encoded in the payload.
/// * `trace_task` - The traceroute task containing destination and TTL information.
/// * `socket` - The socket sender to use for sending the packet.
/// * `src` - Source address bound to this socket
pub fn send_trace(
    worker_id: u32,
    m_id: u32,
    info_url: Option<&str>,
    trace_task: &Trace,
    socket: &Socket,
    src: &Address,
) -> (u32, u32) {
    let target = &trace_task.dst.unwrap(); // Single target for traceroute tasks

    // Store 14 bits of timestamp
    let tx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let timestamp_14b = (tx_time & 0x3FFF) as u16; // store as u14

    // store worker_id as 10bit number (up to 1,024 PoPs)
    let worker_lo_8 = (worker_id & 0xFF) as u16;
    let worker_hi_2 = ((worker_id >> 8) & 0x03) as u16;

    // encode ttl (8 bit) + 8 least significant bits of worker_id
    let sequence_number: u16 = ((trace_task.ttl as u16) << 8) | worker_lo_8;

    // encode 2 most significant bits of worker id and timestamp (14 bits)
    let identifier: u16 = (worker_hi_2 << 14) | timestamp_14b;

    let payload_fields = ProbePayload {
        worker_id,
        m_id,
        trace_ttl: Some(trace_task.ttl as u8),
        info_url,
    };

    // Create the appropriate traceroute packet based on the trace_type
    let packet = &create_icmp(
        src,
        target,
        identifier,      // encode timestamp into identifier field
        sequence_number, // encode TTL (8 bits) and trace ID (8 bits) into seq number
        &payload_fields,
        trace_task.ttl as u8,
        false, // traceroute always uses raw sockets
    );

    // The kernel writes the IPv6 header, so we must set the hop limit on the socket
    if src.is_v6() {
        if let Err(e) = socket.set_unicast_hops_v6(trace_task.ttl) {
            warn!(
                "[Worker outbound] Failed to set IPv6 hop limit to {}: {e}",
                trace_task.ttl
            );
        }
    }

    let result = match send_packet(
        socket,
        packet,
        &trace_task.dst.expect("invalid destination"),
        0,
    ) {
        Ok(()) => (1, 0),
        Err(e) => {
            warn!("[Worker outbound] Failed to send traceroute packet: {e}");
            (0, 1)
        }
    };

    // Restore the default hop limit
    if src.is_v6() {
        let _ = socket.set_unicast_hops_v6(255);
    }

    result
}

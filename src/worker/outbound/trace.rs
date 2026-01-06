use crate::custom_module::manycastr::{Origin, Trace};
use crate::net::packet::{create_icmp, ProbePayload};
use log::{error, warn};
use pnet::datalink::DataLinkSender;
use std::time::{SystemTime, UNIX_EPOCH};

/// Sends a traceroute probe based on the provided trace task and configuration.
/// Only ICMP traceroute is currently implemented.
/// # Arguments
/// * `ethernet_header` - The Ethernet header to prepend to the packet.
/// * `config` - The outbound configuration containing worker details and settings.
/// * `trace_task` - The traceroute task containing destination and TTL information.
/// * `socket_tx` - The socket sender to use for sending the packet.
/// * `origins` - A vector of origins to find the matching origin ID for traceroute tasks.
pub fn send_trace(
    ethernet_header: &[u8],
    worker_id: u32,
    m_id: u32,
    info_url: &str,
    trace_task: &Trace,
    socket_tx: &mut Box<dyn DataLinkSender>,
    origins: &[Origin],
) -> (u32, u32) {
    let target = &trace_task.dst.unwrap(); // Single target for traceroute tasks
    let origin_id = trace_task.origin_id;
    // Get the matching origin for this trace task
    let tx_origin = if let Some(origin) = origins.iter().find(|o| o.origin_id == origin_id) {
        origin
    } else {
        warn!(
            "[Worker outbound] No matching origin found for trace task with origin ID {origin_id}"
        );
        return (0, 1);
    };

    let mut packet = ethernet_header.to_owned();

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
    packet.extend_from_slice(&create_icmp(
        tx_origin.src.as_ref().unwrap(),
        target,
        identifier,      // encode timestamp into identifier field
        sequence_number, // encode TTL (8 bits) and trace ID (8 bits) into seq number
        &payload_fields,
        trace_task.ttl as u8,
    ));

    println!(
        "Sending traceroute with dst {} and ttl {}",
        target, trace_task.ttl
    );

    match socket_tx.send_to(&packet, None) {
        Some(Ok(())) => return (1, 0),
        Some(Err(e)) => warn!("[Worker outbound] Failed to send traceroute packet: {e}"),
        None => error!("[Worker outbound] Failed to send packet: No Tx interface"),
    }
    (0, 1)
}

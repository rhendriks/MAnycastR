use crate::cli::writer::format_rtt;
use crate::custom_module::manycastr::TraceReply;
use bimap::BiHashMap;

/// Get traceroute row
/// format: rx, hop_addr, ttl, tx, trace_dst, trace_ttl, rtt
pub fn get_trace_row(
    reply: TraceReply,
    rx_id: &u32,
    worker_map: &BiHashMap<u32, String>,
) -> Vec<String> {
    // convert the worker ID to hostname
    let rx_hostname = worker_map
        .get_by_left(rx_id)
        .unwrap_or(&String::from("*"))
        .to_string();

    let tx_hostname = worker_map
        .get_by_left(&reply.tx_id)
        .unwrap_or(&String::from("*"))
        .to_string();

    // Set fields to '*' when it is an unresponsive hop
    let hop_addr = if let Some(hop_addr) = reply.hop_addr {
        hop_addr.to_string()
    } else {
        "*".to_string()
    };

    let rtt = if reply.hop_addr.is_some() {
        format_rtt(reply.rtt)
    } else {
        "*".to_string()
    };
    vec![
        rx_hostname,
        hop_addr,
        reply.ttl.to_string(),
        tx_hostname,
        reply.trace_dst.unwrap().to_string(),
        reply.hop_count.to_string(),
        rtt,
    ]
}

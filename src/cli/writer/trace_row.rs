use bimap::BiHashMap;
use crate::cli::writer::{calculate_rtt, calculate_rtt_trace};
use crate::custom_module::manycastr::{Address, Result, TraceReply};

// TODO trace parquet

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
        .unwrap_or(&String::from("Unknown"))
        .to_string();

    let tx_hostname = worker_map
        .get_by_left(&reply.tx_id)
        .unwrap_or(&String::from("Unknown"))
        .to_string();

    // Calculate RTT if tx_time is available
    let rtt = calculate_rtt_trace(reply.rx_time, reply.tx_time);
    vec![
        rx_hostname,
        reply.hop_addr.unwrap().to_string(),
        reply.ttl.to_string(),
        tx_hostname,
        reply.trace_dst.expect("no address").to_string(),
        reply.hop_count.to_string(),
        rtt.to_string(),
    ]
}

use bimap::BiHashMap;
use crate::cli::writer::{calculate_rtt, calculate_rtt_trace};
use crate::custom_module::manycastr::{Address, Reply, TraceReply};

// TODO trace parquet

/// Get traceroute row
/// format: rx, hop_addr, ttl, tx, trace_dst, trace_ttl, rtt
pub fn get_trace_row(
    trace_result: TraceReply,
    rx_id: &u32,
    worker_map: &BiHashMap<u32, String>,
    hop_addr: Address,
    ttl: u8,
) -> Vec<String> {
    // convert the worker ID to hostname
    let rx_hostname = worker_map
        .get_by_left(rx_id)
        .unwrap_or(&String::from("Unknown"))
        .to_string();

    let tx_hostname = worker_map
        .get_by_left(&trace_result.tx_id)
        .unwrap_or(&String::from("Unknown"))
        .to_string();

    // Calculate RTT if tx_time is available
    let rtt = calculate_rtt_trace(trace_result.rx_time, trace_result.tx_time);
    vec![
        rx_hostname,
        hop_addr.to_string(),
        ttl.to_string(),
        tx_hostname,
        trace_result.trace_dst.expect("no address").to_string(),
        trace_result.hop_count.to_string(),
        rtt.to_string(),
    ]
}

use crate::cli::writer::{calculate_rtt, format_rtt};
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

    let hop_addr = if let Some(hop_addr) = reply.hop_addr {
        hop_addr.to_string()
    } else {
        "*".to_string()
    };

    // Pick the RTT decoding by the magnitude of tx_time rather than by hop type. Intermediate
    // hops (all protocols) and the TCP destination carry a 14-bit millisecond timestamp
    // (< 2^14), while the ICMP/DNS destination carries a full microsecond epoch (>> 2^14).
    // This is exact (an epoch-µs value is never < 2^14) and matches the previous hop-type
    // heuristic for ICMP/DNS while also handling the TCP destination correctly.
    let is_traceroute_ts = reply.tx_time < (1 << 14);

    // Calculate RTT if tx_time is available
    let rtt = if reply.hop_addr.is_some() {
        format_rtt(calculate_rtt(
            reply.rx_time,
            reply.tx_time,
            false,
            is_traceroute_ts,
        ))
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

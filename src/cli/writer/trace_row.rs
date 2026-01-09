use crate::cli::writer::calculate_rtt;
use crate::custom_module::manycastr::TraceReply;
use bimap::BiHashMap;

/// Get traceroute row
/// format: rx, hop_addr, ttl, tx, trace_dst, trace_ttl, rtt
pub fn get_trace_row(
    reply: TraceReply,
    rx_id: &u32,
    worker_map: &BiHashMap<u32, String>,
) -> Vec<String> {
    println!("rx_id {}", rx_id);
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

    // Calculate RTT if tx_time is available
    let rtt = calculate_rtt(reply.rx_time, reply.tx_time, false, true);
    vec![
        rx_hostname,
        hop_addr,
        reply.ttl.to_string(),
        tx_hostname,
        reply.trace_dst.unwrap().to_string(),
        reply.hop_count.to_string(),
        rtt.to_string(),
    ]
}

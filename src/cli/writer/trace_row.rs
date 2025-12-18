use bimap::BiHashMap;
use crate::cli::writer::calculate_rtt;
use crate::custom_module::manycastr::Reply;

/// Get traceroute row
/// format: rx, hop_addr, ttl, tx, trace_dst, trace_ttl, rtt
pub fn get_trace_row(
    trace_result: Reply,
    rx_worker_id: &u32,
    _m_type: u8, // TODO ICMP only for now
    worker_map: &BiHashMap<u32, String>,
) -> Vec<String> {
    // convert the worker ID to hostname
    let rx_hostname = worker_map
        .get_by_left(rx_worker_id)
        .unwrap_or(&String::from("Unknown"))
        .to_string();
    let hop_addr = trace_result.src.unwrap().to_string();
    let ttl = trace_result.ttl.to_string();
    let tx_id = trace_result.tx_id;
    let tx_hostname = worker_map
        .get_by_left(&tx_id)
        .unwrap_or(&String::from("Unknown"))
        .to_string();

    // Calculate RTT if tx_time is available
    let rtt = if trace_result.tx_time != 0 {
        format!(
            "{:.2}",
            calculate_rtt(trace_result.rx_time, trace_result.tx_time, false)
        )
    } else {
        String::from("")
    };
    if let Some(trace_ttl) = trace_result.trace_ttl {
        let trace_dst = trace_result.trace_dst.unwrap().to_string();
        // Intermediate hop
        vec![
            rx_hostname,
            hop_addr,
            ttl,
            tx_hostname,
            trace_dst,
            trace_ttl.to_string(),
            rtt,
        ]
    } else {
        // Reply from the destination
        vec![
            rx_hostname,
            hop_addr,
            ttl,
            tx_hostname,
            String::from(""),
            String::from(""),
            rtt,
        ]
    }
}

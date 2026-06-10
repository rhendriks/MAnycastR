use crate::cli::writer::format_rtt;
use crate::custom_module::manycastr::MeasurementReply;
use crate::SINGLE_ORIGIN;
use bimap::BiHashMap;

/// Get the result (csv row) from a Reply message
///
/// # Arguments
/// * `reply` - The Reply that is being written to this row
/// * `rx_worker_id` - The worker ID of the receiver
/// * `worker_map` - A map of worker IDs to hostnames, used to convert worker IDs to hostnames in the results
/// * `origin_id` - origin ID associated with the reply
///
/// # Returns
/// A vector of strings representing the row in the CSV file
pub fn get_latency_row(
    reply: MeasurementReply,
    rx_worker_id: &u32,
    worker_map: &BiHashMap<u32, String>,
    origin_id: u32,
) -> Vec<String> {
    // convert the worker ID to hostname
    let rx_hostname = worker_map
        .get_by_left(rx_worker_id)
        .unwrap_or(&String::from("Unknown"))
        .to_string();

    let mut row = vec![
        rx_hostname,
        reply.src.unwrap().to_string(),
        reply.ttl.to_string(),
        format_rtt(reply.rtt),
    ];

    // Optional fields
    if origin_id != SINGLE_ORIGIN {
        row.push(origin_id.to_string());
    }

    row
}

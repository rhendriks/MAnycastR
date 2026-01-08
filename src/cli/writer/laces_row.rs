use crate::custom_module::manycastr::MeasurementReply;
use bimap::BiHashMap;

/// Get the result (csv row) from a Reply message
///
/// # Arguments
/// * `reply` - The Reply that is being written to this row
/// * `rx_worker_id` - The worker ID of the receiver
/// * `is_tcp` - TCP measurements have different tx time formats
/// * `worker_map` - A map of worker IDs to hostnames, used to convert worker IDs to hostnames in the results
///
/// # Returns
/// A vector of strings representing the row in the CSV file
pub fn get_laces_row(
    reply: MeasurementReply,
    rx_worker_id: &u32,
    is_tcp: bool,
    worker_map: &BiHashMap<u32, String>,
) -> Vec<String> {
    // convert the worker ID to hostname
    let rx_hostname = worker_map
        .get_by_left(rx_worker_id)
        .unwrap_or(&String::from("Unknown"))
        .to_string();

    let tx_hostname = worker_map
        .get_by_left(&reply.tx_id)
        .unwrap_or(&String::from("Unknown"))
        .to_string();

    let rx_time = if is_tcp {
        // convert to milliseconds and mask to 21 bits
        let rx_ms = reply.rx_time / 1000;
        let rx_wrapped = rx_ms & 0x1FFFFF;
        rx_wrapped.to_string()
    } else {
        reply.rx_time.to_string()
    };

    let mut row = vec![
        rx_hostname,
        rx_time,
        reply.src.unwrap().to_string(),
        reply.ttl.to_string(),
        reply.tx_time.to_string(),
        tx_hostname,
    ];

    // Optional fields
    if let Some(chaos) = reply.chaos {
        row.push(chaos);
    }
    if reply.origin_id != 0 {
        row.push(reply.origin_id.to_string());
    }

    row
}

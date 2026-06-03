use crate::cli::writer::calculate_rtt;
use crate::custom_module::manycastr::MeasurementReply;
use crate::SINGLE_ORIGIN;
use bimap::BiHashMap;

/// Get the result (csv row) from a Reply message
///
/// # Arguments
/// * `reply` - The Reply that is being written to this row
/// * `rx_worker_id` - The worker ID of the receiver
/// * `is_tcp` - TCP measurements encode the tx time as a 21-bit timestamp
/// * `worker_map` - A map of worker IDs to hostnames, used to convert worker IDs to hostnames in the results
/// * `origin_id` - Associated origin ID of the reply
///
/// # Returns
/// A vector of strings representing the row in the CSV file
///
/// # Note
/// The `rtt` column carries the signed offset `rx_time - tx_time` (milliseconds).
/// Under anycast the sender (`tx`) and receiver (`rx`) may be different PoPs,
/// and may be negative; see [`calculate_rtt`].
pub fn get_laces_row(
    reply: MeasurementReply,
    rx_worker_id: &u32,
    is_tcp: bool,
    worker_map: &BiHashMap<u32, String>,
    origin_id: u32,
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

    let rtt = calculate_rtt(reply.rx_time, reply.tx_time, is_tcp, false);

    let mut row = vec![
        rx_hostname,
        reply.src.unwrap().to_string(),
        reply.ttl.to_string(),
        tx_hostname,
        rtt.to_string(),
    ];

    // Optional fields
    if let Some(chaos) = reply.chaos {
        row.push(chaos);
    }
    if origin_id != SINGLE_ORIGIN {
        row.push(origin_id.to_string());
    }

    row
}

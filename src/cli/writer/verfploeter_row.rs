use crate::custom_module::manycastr::ProbeMeasurement;
use bimap::BiHashMap;

/// Get the result (csv row) from a Reply message
///
/// # Arguments
/// * `result` - The Reply that is being written to this row
/// * `rx_worker_id` - The worker ID of the receiver
/// * `m_type` - The type of measurement being performed
/// * `is_symmetric` - A boolean that determines whether the measurement is symmetric (i.e., sender == receiver is always true)
/// * `worker_map` - A map of worker IDs to hostnames, used to convert worker IDs to hostnames in the results
/// * `is_record` - A boolean that determines whether Record Route is included
///
/// # Returns
///
/// A vector of strings representing the row in the CSV file
pub fn get_verfploeter_csv_row(
    reply: ProbeMeasurement,
    rx_id: &u32,
    worker_map: &BiHashMap<u32, String>,
) -> Vec<String> {
    // convert the worker ID to hostname
    let rx_hostname = worker_map
        .get_by_left(rx_id)
        .unwrap_or(&String::from("Unknown"))
        .to_string();

    let mut row = vec![
        rx_hostname,
        reply.src.unwrap().to_string(),
        reply.ttl.to_string(),
    ];

    // Optional fields
    if let Some(chaos) = reply.chaos {
        row.push(chaos.to_string());
    }
    if reply.origin_id != 0 {
        row.push(reply.origin_id.to_string());
    }

    row
}

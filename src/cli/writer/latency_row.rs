use bimap::BiHashMap;
use crate::cli::writer::calculate_rtt;
use crate::cli::writer::parquet_writer::ParquetDataRow;
use crate::custom_module::manycastr::{Address, LacesReply, LatencyReply, Reply};
use crate::{CHAOS_ID, TCP_ID};

/// Represents a row of LACeS data in the Parquet file format.
pub struct LatencyParquetDataRow {
    /// Hostname of the probe receiver.
    rx: String,
    /// Measured RTT (milliseconds)
    rtt: f64,
    /// Source address of the reply (as a string).
    addr: String,
    /// Time-to-live (TTL) value of the reply.
    ttl: u8,
    /// Origin ID for multi-origin measurements (source address, ports).
    origin_id: Option<u8>,

    chaos_data: Option<String>,
}

/// Converts a Reply message into a ParquetDataRow for writing to a Parquet file.
pub fn latency_reply_to_parquet_row(
    src: Address,
    ttl: u8,
    result: LatencyReply,
    rx_id: u16,
    m_type: u8,
    worker_map: &BiHashMap<u16, String>,
    origin_id: Option<u8>, // Only set when multiple origins are used (i.e., origin_id != 0) [or when origin_id == U32::MAX] TODO when is u32 max used for origin id?
    chaos_data: Option<String>,
) -> LatencyParquetDataRow {
    let rtt = calculate_rtt(result.rx_time, result.tx_time, m_type == TCP_ID);

    LatencyParquetDataRow {
        rx: worker_map.get_by_left(&rx_id).expect("Unknown worker ID").clone(),
        addr: src.to_string(),
        ttl,
        rtt,
        origin_id,
        chaos_data,
    }
}

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
pub fn get_latency_row(
                result: LatencyReply,
                rx_worker_id: &u32,
                worker_map: &BiHashMap<u32, String>,
                chaos_data: Option<String>,
                origin_id: Option<u32>,
                src: Address,
                m_type: u8,
                ttl: u8,
) -> Vec<String> {
    // convert the worker ID to hostname
    let rx_hostname = worker_map
        .get_by_left(rx_worker_id)
        .unwrap_or(&String::from("Unknown"))
        .to_string();

    let rtt = calculate_rtt(result.rx_time, result.tx_time, m_type == TCP_ID);

    let mut row = vec![rx_hostname, rtt.to_string(), src.to_string(), ttl.to_string()];

    // Optional fields
    if let Some(chaos) = chaos_data {
        row.push(chaos);
    }
    if let Some(id) = origin_id {
        row.push(id.to_string());
    }

    row
}

use bimap::BiHashMap;
use crate::cli::writer::calculate_rtt;
// use crate::cli::writer::parquet_writer::ParquetDataRow;
use crate::custom_module::manycastr::{Address, LacesReply, Result};
use crate::{CHAOS_ID, TCP_ID};

/// Represents a row of LACeS data in the Parquet file format.
pub struct LacesParquetDataRow {
    /// Hostname of the probe receiver.
    rx: String,
    /// UNIX timestamp in microseconds when the reply was received.
    rx_time: u64,
    /// Source address of the reply (as a string).
    addr: String,
    /// Time-to-live (TTL) value of the reply.
    ttl: u8,
    /// UNIX timestamp in microseconds when the request was sent. [unavailable for TCP]
    tx_time: Option<u64>,
    /// Hostname of the probe sender.
    tx: String,
    /// DNS TXT CHAOS record value.
    chaos_data: Option<String>,
    /// Origin ID for multi-origin measurements (source address, ports).
    origin_id: Option<u8>,
}

/// Converts a Reply message into a ParquetDataRow for writing to a Parquet file.
pub fn laces_reply_to_parquet_row(
    src: Address,
    ttl: u8,
    result: LacesReply,
    rx_id: u16,
    worker_map: &BiHashMap<u16, String>,
    chaos_data: Option<String>,
    origin_id: Option<u8>, // Only set when multiple origins are used (i.e., origin_id != 0) [or when origin_id == U32::MAX] TODO when is u32 max used for origin id?
) -> LacesParquetDataRow {
    LacesParquetDataRow {
        rx: worker_map.get_by_left(&rx_id).expect("Unknown worker ID").clone(),
        rx_time: result.rx_time,
        addr: src.to_string(),
        ttl,
        tx_time: result.tx_time,
        tx: worker_map.get_by_left(&(result.tx_id as u16)).expect("Unknown worker ID").clone(),
        chaos_data,
        origin_id,
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
pub fn get_laces_row(
    reply: LacesReply,
                rx_worker_id: &u32,
                m_type: u8,
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

    let mut row = if m_type == TCP_ID {
        // TCP has no tx_time
        vec![rx_hostname, reply.rx_time.to_string(), reply.src.unwrap().to_string(), reply.ttl.to_string(), tx_hostname]
    } else {
        vec![rx_hostname, reply.rx_time.to_string(), reply.src.unwrap().to_string(), reply.ttl.to_string(), reply.tx_time.expect("no tx_time").to_string(), tx_hostname]
    };


    // Optional fields
    if let Some(chaos) = reply.chaos {
        row.push(chaos);
    }
    if let Some(id) = reply.origin_id {
        row.push(id.to_string());
    }

    row
}

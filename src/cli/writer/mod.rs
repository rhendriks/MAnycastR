use std::fs::File;
use std::io;
use std::io::Write;

use bimap::BiHashMap;
use csv::Writer;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::cli::writer::csv_writer::get_csv_metadata;
use crate::cli::writer::laces_row::get_laces_row;
use crate::cli::writer::latency_row::get_latency_row;
use crate::{custom_module, CHAOS_ID};
use custom_module::manycastr::{Configuration, Reply, ReplyBatch};
use flate2::write::GzEncoder;
use flate2::Compression;
use log::error;
use std::io::BufWriter;
// use crate::cli::writer::parquet_writer::{build_parquet_schema, get_parquet_metadata, write_batch_to_parquet, ParquetDataRow};
use crate::cli::writer::trace_row::get_trace_row;
use crate::cli::writer::verfploeter_row::get_verfploeter_csv_row;
use crate::custom_module::manycastr::reply::ReplyData;

pub mod csv_writer;
mod laces_row;
mod latency_row;
pub mod parquet_writer;
mod trace_row;
mod verfploeter_row;

/// Configuration for the results writing process.
pub struct WriteConfig<'a> {
    /// Determines whether the results should also be printed to the command-line interface.
    pub print_to_cli: bool,
    /// The file handle to which the measurement results should be written.
    pub output_file: File,
    /// Metadata for the measurement, to be written at the beginning of the output file.
    pub metadata_args: MetadataArgs<'a>,
    /// The type of measurement being performed, influencing how results are processed or formatted.
    /// (e.g., 1 for ICMP, 2 for DNS/A, 3 for TCP, 4 for DNS/CHAOS, etc.)
    pub m_type: u8,
    /// Indicates whether the measurement involves multiple origins, which affects
    /// how results are written.
    pub is_multi_origin: bool,
    /// Indicates whether the measurement is symmetric (e.g., sender == receiver is always true),
    /// to simplify certain result interpretations.
    pub is_symmetric: bool,
    /// A bidirectional map used to convert worker IDs (u16) to their corresponding hostnames (String).
    pub worker_map: BiHashMap<u32, String>,
    /// Indicate whether it is a traceroute measurement
    pub is_traceroute: bool,
    /// Indicate whether Record Route is used
    pub is_record: bool,
    /// Indicate whether this is a Verfploeter catchment mapping (single probe per target from any worker)
    pub is_verfploeter: bool,
}

/// Holds all the arguments required to metadata for the output file.
pub struct MetadataArgs<'a> {
    /// Divide-and-conquer measurement flag.
    pub is_divide: bool,
    /// Path to the hitlist used.
    pub hitlist: &'a str,
    /// Whether the hitlist was shuffled.
    pub is_shuffle: bool,
    /// A string representation of the measurement type (e.g., "ICMP", "DNS").
    pub m_type_str: String,
    /// The probing rate used.
    pub probing_rate: u32,
    /// The interval between subsequent workers.
    pub interval: u32,
    /// A bidirectional map of all possible worker IDs to their hostnames.
    pub all_workers: &'a BiHashMap<u32, String>,
    /// Optional configuration file used.
    pub configurations: &'a Vec<Configuration>,
    /// Whether this is a configuration-based measurement.
    pub is_config: bool,
    /// Whether this is a latency-based measurement.
    pub is_latency: bool,
    /// Whether this is a responsiveness-based measurement.
    pub is_responsive: bool,
}

/// Writes the results to a file (and optionally to the command-line)
///
/// # Arguments
/// * 'rx' - The receiver channel that receives the results
/// * 'config' - The configuration for writing results, including file handle, metadata, and measurement type
pub fn write_results(
    mut rx: UnboundedReceiver<ReplyBatch>,
    config: WriteConfig
) {
    // CSV writer to command-line interface
    let mut wtr_cli = config
        .print_to_cli
        .then(|| Writer::from_writer(io::stdout()));

    let buffered_file_writer = BufWriter::new(config.output_file);
    let mut gz_encoder = GzEncoder::new(buffered_file_writer, Compression::default());

    // Write metadata to file
    let md_lines = get_csv_metadata(config.metadata_args, &config.worker_map);
    for line in md_lines {
        if let Err(e) = writeln!(gz_encoder, "{line}") {
            error!("Failed to write metadata line to Gzip stream: {e}");
        }
    }

    // .gz writer
    let mut wtr_file = Writer::from_writer(gz_encoder);

    // Write header
    let header = get_header(
        config.m_type,
        config.is_multi_origin,
        config.is_symmetric,
        config.is_traceroute,
        config.is_record,
        config.is_verfploeter,
    );
    if let Some(wtr) = wtr_cli.as_mut() {
        wtr.write_record(&header)
            .expect("Failed to write header to stdout")
    };
    wtr_file
        .write_record(header)
        .expect("Failed to write header to file");

    tokio::spawn(async move {
        // Receive task results from the outbound channel
        while let Some(task_result) = rx.recv().await {
            if task_result == ReplyBatch::default() {
                break;
            }
            let results: Vec<Reply> = task_result.results;
            let rx_id = task_result.rx_id;

            for result in results {
                let row = match result.reply_data {
                    Some(data) => match data {
                        ReplyData::Measurement(reply) => {
                            if config.is_symmetric {
                                get_latency_row(reply, &rx_id, &config.worker_map, config.m_type)
                            } else if config.is_verfploeter {
                                get_verfploeter_csv_row(reply, &rx_id, &config.worker_map)
                            } else {
                                get_laces_row(reply, &rx_id, config.m_type, &config.worker_map)
                            }
                        }
                        ReplyData::Trace(reply) => {
                            get_trace_row(reply, &rx_id, &config.worker_map)
                        }
                        ReplyData::Discovery(_) => panic!("Discovery result forwarded to CLI"),
                    },
                    None => {
                        panic!("Reply contained no result data!");
                    }
                };
                // Write to command-line
                if let Some(ref mut wtr) = wtr_cli {
                    wtr.write_record(&row)
                        .expect("Failed to write payload to CLI");
                    wtr.flush().expect("Failed to flush stdout");
                }

                // Write to file
                wtr_file
                    .write_record(row)
                    .expect("Failed to write payload to file");
            }
            wtr_file.flush().expect("Failed to flush file");
        }
        rx.close();
        wtr_file.flush().expect("Failed to flush file");
    });
}

/// Creates the appropriate CSV header for the results file (based on the measurement type)
///
/// # Arguments
///
/// * 'measurement_type' - The type of measurement being performed
/// * 'is_multi_origin' - A boolean that determines whether multiple origins are used
/// * 'is_symmetric' - A boolean that determines whether the measurement is symmetric (i.e., sender == receiver is always true)
/// * 'is_traceroute' - A boolean that determines whether the measurement is a traceroute
/// * 'is_record' - A boolean that determines whether Record Route is used
pub fn get_header(
    m_type: u8,
    is_multi_origin: bool,
    is_latency: bool,
    is_traceroute: bool,
    is_record: bool,
    is_verfploeter: bool,
) -> Vec<&'static str> {
    let mut header = if is_traceroute {
        vec![
            "rx",
            "hop_addr",
            "ttl",
            "tx",
            "trace_dst",
            "trace_ttl",
            "rtt",
        ]
    } else if is_latency {
        vec!["rx", "addr", "ttl", "rtt"]
    }else if is_verfploeter {
        vec!["rx", "addr", "ttl"]
    } else {
        vec!["rx", "rx_time", "addr", "ttl", "tx_time", "tx"]
    };

    // Optional fields
    if m_type == CHAOS_ID {
        header.push("chaos_data");
    }
    if is_multi_origin {
        header.push("origin_id");
    }
    if is_record {
        header.push("record_route");
    }

    header
}

pub fn calculate_rtt(rx_time: u64, tx_time: u64, is_tcp: bool) -> f64 {
    if is_tcp {
        // 21 bit millisecond timestamp
        const MODULUS: u64 = 1 << 21; // 2,097,152
        const MASK: u64 = MODULUS - 1; // 0x1FFFFF

        // convert rx_time to milliseconds
        let rx_time_ms = rx_time / 1_000;

        // match tx_time format (21 bits)
        let rx_21b = rx_time_ms & MASK;

        // ensure tx_time is masked
        let tx_21b = tx_time & MASK;

        // calculate difference
        let rtt_ms = if rx_21b >= tx_21b {
            rx_21b - tx_21b
        } else {
            // wrap-around case
            (rx_21b + MODULUS) - tx_21b
        };

        rtt_ms as f64
    } else {
        (rx_time - tx_time) as f64 / 1_000.0
    }
}

/// Calculates RTT handling the 14-bit timestamp wrap-around.
///
/// * `rx_time_us`: Receive time in milliseconds
/// * `tx_time_ms_14b`: Transmit time in milliseconds (masked to 14 bits).
pub fn calculate_rtt_trace(rx_time: u32, tx_time: u32) -> f64 {
    // 14-bit Modulus (2^14 = 16384)
    const MODULUS: u32 = 1 << 14;
    const MASK: u32 = MODULUS - 1; // 0x3FFF

    let rx_14b = rx_time & MASK;

    let rtt_ms = if rx_14b >= tx_time {
        rx_14b - tx_time
    } else {
        // wrap around
        (rx_14b + MODULUS) - tx_time
    };

    rtt_ms as f64
}

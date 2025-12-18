use std::fs::File;
use std::io;
use std::io::Write;

use bimap::BiHashMap;
use csv::Writer;
use tokio::sync::mpsc::UnboundedReceiver;

use custom_module::manycastr::{Configuration, Reply, TaskResult};
use custom_module::Separated;
use flate2::write::GzEncoder;
use flate2::Compression;
use log::error;
use parquet::basic::{Compression as ParquetCompression, LogicalType, Repetition};
use parquet::data_type::{ByteArray, DoubleType, Int32Type, Int64Type};
use parquet::file::properties::WriterProperties;
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::types::{Type as SchemaType, TypePtr};
use std::io::BufWriter;
use std::sync::Arc;
use crate::{custom_module, ALL_WORKERS, CHAOS_ID, TCP_ID};
use crate::cli::writer::csv_writer::{get_csv_metadata};
use crate::cli::writer::latency_row::get_latency_row;
use crate::cli::writer::parquet_writer::{build_parquet_schema, get_parquet_metadata, write_batch_to_parquet, ParquetDataRow};
use crate::cli::writer::trace_row::get_trace_row;
use crate::cli::writer::verfploeter_row::get_verfploeter_csv_row;
use crate::custom_module::manycastr::reply::ResultData;

pub mod parquet_writer;
pub mod csv_writer;
mod laces_row;
mod latency_row;
mod verfploeter_row;
mod trace_row;

/// Configuration for the results writing process.
///
/// This struct bundles all the necessary parameters for `write_results`
/// to determine where and how to output measurement results,
/// including formatting options and contextual metadata.
pub struct WriteConfig<'a> {
    /// Determines whether the results should also be printed to the command-line interface.
    pub print_to_cli: bool,
    /// The file handle to which the measurement results should be written.
    pub output_file: File,
    /// Metadata for the measurement, to be written at the beginning of the output file.
    pub metadata_args: MetadataArgs<'a>,
    /// The type of measurement being performed, influencing how results are processed or formatted.
    /// (e.g., 1 for ICMP, 2 for DNS/A, 3 for TCP, 4 for DNS/CHAOS, etc.)
    pub m_type: u32,
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
///
/// * 'rx' - The receiver channel that receives the results
///
/// * 'config' - The configuration for writing results, including file handle, metadata, and measurement type
pub fn write_results(mut rx: UnboundedReceiver<TaskResult>, config: WriteConfig) {
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
            if task_result == TaskResult::default() {
                break;
            }
            let results: Vec<Reply> = task_result.replies;;
            let rx_id = task_result.rx_id;

            for result in results {
                let src = result.src.expect("no address");
                let ttl = result.ttl as u8;
                let chaos_data = result.chaos;
                let origin_id = result.origin_id;
                let row = match result.result_data {
                    Some(data) => match data {
                        ResultData::VerfploeterReply(_) => {
                            get_verfploeter_csv_row(
                                &rx_id,
                                &config.worker_map,
                                origin_id,
                                ttl,
                                src,
                                chaos_data,
                            )
                        },
                        ResultData::LatencyReply(reply) => {
                            get_latency_row(
                                reply,
                                &rx_id,
                                &config.worker_map,
                                chaos_data,
                                origin_id,
                                src,
                                config.m_type as u8,
                                ttl,
                            )
                        },
                        ResultData::LacesReply(reply) => {
                            // ...
                        },
                        ResultData::TraceReply(reply) => {
                            // ...
                        },
                        ResultData::RecordReply(reply) => {
                            // ...
                        },
                    },
                    None => {
                        eprintln!("Reply contained no result data!");
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

const ROW_BUFFER_CAPACITY: usize = 50_000; // Number of rows to buffer before writing (impacts RAM usage)
const MAX_ROW_GROUP_SIZE_BYTES: usize = 256 * 1024 * 1024; // 256 MB

/// Write results to a Parquet file as they are received from the channel.
/// This function processes the results in batches to optimize writing performance.
///
/// # Arguments
///
/// * `rx` - The receiver channel that receives the results.
///
/// * `config` - The configuration for writing results, including file handle, metadata, and measurement type.
pub fn write_results_parquet(mut rx: UnboundedReceiver<TaskResult>, config: WriteConfig) {
    let schema = build_parquet_schema(
        config.m_type,
        config.is_multi_origin,
        config.is_symmetric,
        config.is_traceroute,
        config.is_record,
    );

    // Get metadata key-value pairs for the Parquet file
    let key_value_tuples = get_parquet_metadata(config.metadata_args, &config.worker_map);

    // Configure writer properties, including compression and metadata
    let key_value_metadata: Vec<parquet::file::metadata::KeyValue> = key_value_tuples
        .into_iter()
        .map(|(key, value)| parquet::file::metadata::KeyValue::new(key, value))
        .collect();

    let props = Arc::new(
        WriterProperties::builder()
            .set_compression(ParquetCompression::SNAPPY)
            .set_key_value_metadata(Some(key_value_metadata)) // Use the clean metadata
            .set_max_row_group_size(MAX_ROW_GROUP_SIZE_BYTES) // Set max row group size
            .build(),
    );

    let mut writer = SerializedFileWriter::new(config.output_file, schema.clone(), props)
        .expect("Failed to create parquet writer");

    // Get the appropriate header for the Parquet file based on the measurement type and configuration
    let headers = get_header(
        config.m_type,
        config.is_multi_origin,
        config.is_symmetric,
        config.is_traceroute,
        config.is_record,
    );

    tokio::spawn(async move {
        let mut row_buffer: Vec<ParquetDataRow> = Vec::with_capacity(ROW_BUFFER_CAPACITY);

        while let Some(task_result) = rx.recv().await {
            if task_result == TaskResult::default() {
                break; // End of stream
            }

            let worker_id = task_result.worker_id;
            for reply in task_result.result_list {
                let parquet_row = reply_to_parquet_row(
                    reply,
                    worker_id,
                    config.m_type as u8,
                    config.is_symmetric,
                    &config.worker_map,
                );
                row_buffer.push(parquet_row);
            }

            // If the buffer is full, write the batch to the file
            if row_buffer.len() >= ROW_BUFFER_CAPACITY {
                write_batch_to_parquet(&mut writer, &row_buffer, &headers)
                    .expect("Failed to write batch to Parquet file");
                row_buffer.clear();
            }
        }

        // Write any remaining rows in the buffer
        if !row_buffer.is_empty() {
            write_batch_to_parquet(&mut writer, &row_buffer, &headers)
                .expect("Failed to write final batch to Parquet file");
        }

        writer.close().expect("Failed to close Parquet writer");
        rx.close();
    });
}

/// Creates the appropriate CSV header for the results file (based on the measurement type)
///
/// # Arguments
///
/// * 'measurement_type' - The type of measurement being performed
///
/// * 'is_multi_origin' - A boolean that determines whether multiple origins are used
///
/// * 'is_symmetric' - A boolean that determines whether the measurement is symmetric (i.e., sender == receiver is always true)
///
/// * 'is_traceroute' - A boolean that determines whether the measurement is a traceroute
///
/// * 'is_record' - A boolean that determines whether Record Route is used
pub fn get_header(
    m_type: u32,
    is_multi_origin: bool,
    is_symmetric: bool,
    is_traceroute: bool,
    is_record: bool,
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
    } else if is_symmetric {
        vec!["rx", "addr", "ttl", "rtt"]
    } else {
        // TCP anycast does not have tx_time
        if m_type == TCP_ID as u32 {
            vec!["rx", "rx_time", "addr", "ttl", "tx"]
        } else {
            vec!["rx", "rx_time", "addr", "ttl", "tx_time", "tx"]
        }
    };

    // Optional fields
    if m_type == CHAOS_ID as u32 {
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
        let rx_time_ms = rx_time / 1_000;
        let rx_time_adj = rx_time_ms as u32;

        (rx_time_adj - tx_time as u32) as f64
    } else {
        (rx_time - tx_time) as f64 / 1_000.0
    }
}

// rx_time (microsends timestamp) tx_time (microseconds timestamp)
pub fn calculate_rtt_trace(rx_time: u32, tx_time: u32) -> f64 {
    // Treat timestamps as wrapping 16-bit values
    const MODULUS: u32 = u16::MAX as u32 + 1;

    let rtt_ms = if rx_time >= tx_time {
        rx_time - tx_time
    } else {
        // Handle wrap-around
        (MODULUS - tx_time) + rx_time
    };

    rtt_ms as f64
}


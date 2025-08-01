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
use std::io::BufWriter;
use std::sync::Arc;

use parquet::basic::{Compression as ParquetCompression, LogicalType, Repetition};
use parquet::data_type::{ByteArray, DoubleType, Int32Type, Int64Type};
use parquet::file::properties::WriterProperties;
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::types::{Type as SchemaType, TypePtr};

use crate::{custom_module, CHAOS_ID, TCP_ID};

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
    /// A bidirectional map used to convert worker IDs (u32) to their corresponding hostnames (String).
    pub worker_map: BiHashMap<u32, String>,
}

/// Holds all the arguments required to metadata for the output file.
pub struct MetadataArgs<'a> {
    /// Divide-and-conquer measurement flag.
    pub is_divide: bool,
    /// The origins used in the measurement.
    pub origin_str: String,
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
    /// Hostnames of the workers selected to probe.
    pub active_workers: Vec<String>,
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
    let mut wtr_cli = if config.print_to_cli {
        Some(Writer::from_writer(io::stdout()))
    } else {
        None
    };

    let buffered_file_writer = BufWriter::new(config.output_file);
    let mut gz_encoder = GzEncoder::new(buffered_file_writer, Compression::default());

    // Write metadata to file
    let md_lines = get_csv_metadata(config.metadata_args, &config.worker_map);
    for line in md_lines {
        if let Err(e) = writeln!(gz_encoder, "{}", line) {
            eprintln!("Failed to write metadata line to Gzip stream: {}", e);
        }
    }

    // .gz writer
    let mut wtr_file = Writer::from_writer(gz_encoder);

    // Write header
    let header = get_header(config.m_type, config.is_multi_origin, config.is_symmetric);
    if let Some(wtr) = wtr_cli.as_mut() {
        wtr.write_record(&header)
            .expect("Failed to write header to stdout")
    };
    wtr_file
        .write_record(header)
        .expect("Failed to write header to file");

    tokio::spawn(async move {
        // Receive tasks from the outbound channel
        while let Some(task_result) = rx.recv().await {
            if task_result == TaskResult::default() {
                break;
            }
            let results: Vec<Reply> = task_result.result_list;
            for result in results {
                let result = get_row(
                    result,
                    task_result.worker_id,
                    config.m_type as u8,
                    config.is_symmetric,
                    config.worker_map.clone(),
                );

                // Write to command-line
                if let Some(ref mut wtr) = wtr_cli {
                    wtr.write_record(&result)
                        .expect("Failed to write payload to CLI");
                    wtr.flush().expect("Failed to flush stdout");
                }

                // Write to file
                wtr_file
                    .write_record(result)
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
///
/// * 'is_multi_origin' - A boolean that determines whether multiple origins are used
///
/// * 'is_symmetric' - A boolean that determines whether the measurement is symmetric (i.e., sender == receiver is always true)
pub fn get_header(m_type: u32, is_multi_origin: bool, is_symmetric: bool) -> Vec<&'static str> {
    let mut header = if is_symmetric {
        vec!["rx", "addr", "ttl", "rtt"]
    } else {
        // TCP anycast does not have tx_time
        if m_type == TCP_ID as u32 {
            vec!["rx", "rx_time", "addr", "ttl", "tx"]
        } else {
            vec!["rx", "rx_time", "addr", "ttl", "tx_time", "tx"]
        }
    };

    if m_type == CHAOS_ID as u32 {
        header.push("chaos_data");
    }

    if is_multi_origin {
        header.push("origin_id");
    }

    header
}

/// Get the result (csv row) from a Reply message
///
/// # Arguments
///
/// * `result` - The Reply that is being written to this row
///
/// * `rx_worker_id` - The worker ID of the receiver
///
/// * `m_type` - The type of measurement being performed
///
/// * `is_symmetric` - A boolean that determines whether the measurement is symmetric (i.e., sender == receiver is always true)
///
/// * `worker_map` - A map of worker IDs to hostnames, used to convert worker IDs to hostnames in the results
///
/// # Returns
///
/// A vector of strings representing the row in the CSV file
fn get_row(
    result: Reply,
    rx_worker_id: u32,
    m_type: u8,
    is_symmetric: bool,
    worker_map: BiHashMap<u32, String>,
) -> Vec<String> {
    let origin_id = result.origin_id.to_string();
    let is_multi_origin = result.origin_id != 0 && result.origin_id != u32::MAX;
    let rx_worker_id = rx_worker_id.to_string();
    // convert the worker ID to hostname
    let rx_hostname = worker_map
        .get_by_left(&rx_worker_id.parse::<u32>().unwrap())
        .unwrap_or(&String::from("Unknown"))
        .to_string();
    let rx_time = result.rx_time.to_string();
    let tx_time = result.tx_time.to_string();
    let tx_id = result.tx_id;
    let ttl = result.ttl.to_string();
    let reply_src = result.src.unwrap().to_string();

    let mut row = if is_symmetric {
        let rtt = format!(
            "{:.2}",
            calculate_rtt(result.rx_time, result.tx_time, m_type == TCP_ID)
        );
        vec![rx_hostname, reply_src, ttl, rtt]
    } else {
        let tx_hostname = worker_map
            .get_by_left(&tx_id)
            .unwrap_or(&String::from("Unknown"))
            .to_string();

        // TCP anycast does not have tx_time
        if m_type == TCP_ID {
            vec![rx_hostname, rx_time, reply_src, ttl, tx_hostname]
        } else {
            vec![rx_hostname, rx_time, reply_src, ttl, tx_time, tx_hostname]
        }
    };

    // Optional fields
    if let Some(chaos) = result.chaos {
        row.push(chaos);
    }
    if is_multi_origin {
        row.push(origin_id);
    }

    row
}

pub fn calculate_rtt(rx_time: u64, tx_time: u64, is_tcp: bool) -> f64 {
    if is_tcp {
        // Convert rx_time from nanoseconds to milliseconds (to match tx_time)
        let rx_time_ms = rx_time / 1_000_000;

        // Get the lower 32 bits of the rx_time in milliseconds
        let rx_time_adj = rx_time_ms as u32;

        // Calculate the RTT in milliseconds
        (rx_time_adj - tx_time as u32) as f64
    } else {
        (rx_time - tx_time) as f64 / 1_000_000.0
    }
}

/// Returns a vector of lines containing the metadata of the measurement
///
/// # Arguments
///
/// Variables describing the measurement
pub fn get_csv_metadata(
    args: MetadataArgs<'_>,
    worker_map: &BiHashMap<u32, String>,
) -> Vec<String> {
    let mut md_file = Vec::new();
    if args.is_divide {
        md_file.push("# Measurement style: Divide-and-conquer".to_string());
    } else if args.is_latency {
        md_file.push("# Measurement style: Anycast latency".to_string());
    } else if args.is_responsive {
        md_file.push("# Measurement style: Responsive-mode".to_string());
    }
    md_file.push(format!("# Origin used: {}", args.origin_str));
    md_file.push(format!(
        "# Hitlist{}: {}",
        if args.is_shuffle { " (shuffled)" } else { "" },
        args.hitlist
    ));
    md_file.push(format!("# Measurement type: {}", args.m_type_str));
    md_file.push(format!(
        "# Probing rate: {}",
        args.probing_rate.with_separator()
    ));
    md_file.push(format!("# Worker interval: {}", args.interval));
    if !args.active_workers.is_empty() {
        md_file.push(format!(
            "# Selective probing using the following workers: {:?}",
            args.active_workers
        ));
    }
    md_file.push(format!("# {} connected workers:", args.all_workers.len()));
    for (_, hostname) in args.all_workers {
        md_file.push(format!("# * {}", hostname))
    }

    // Write configurations used for the measurement
    if args.is_config {
        md_file.push("# Configurations:".to_string());
        for configuration in args.configurations {
            let origin = configuration.origin.unwrap();
            let src = origin.src.expect("Invalid source address");
            let hostname = if configuration.worker_id == u32::MAX {
                "ALL".to_string()
            } else {
                worker_map
                    .get_by_left(&configuration.worker_id)
                    .unwrap_or(&String::from("Unknown"))
                    .to_string()
            };
            md_file.push(format!(
                "# * {:<2}, source IP: {}, source port: {}, destination port: {}",
                hostname, src, origin.sport, origin.dport
            ));
        }
    }

    md_file
}

/// Returns a vector of key-value pairs containing the metadata of the measurement.
pub fn get_parquet_metadata(
    args: MetadataArgs<'_>,
    worker_map: &BiHashMap<u32, String>,
) -> Vec<(String, String)> {
    let mut md = Vec::new();

    if args.is_divide {
        md.push((
            "measurement_style".to_string(),
            "Divide-and-conquer".to_string(),
        ));
    }
    if args.is_latency {
        md.push((
            "measurement_style".to_string(),
            "Anycast-latency".to_string(),
        ));
    }
    if args.is_responsive {
        md.push((
            "measurement_style".to_string(),
            "Responsive-mode".to_string(),
        ));
    }

    md.push(("origin_used".to_string(), args.origin_str));
    md.push(("hitlist_path".to_string(), args.hitlist.to_string()));
    md.push(("hitlist_shuffled".to_string(), args.is_shuffle.to_string()));
    md.push(("measurement_type".to_string(), args.m_type_str));
    // Store numbers without separators for easier parsing later
    md.push((
        "probing_rate_pps".to_string(),
        args.probing_rate.to_string(),
    ));
    md.push(("worker_interval_ms".to_string(), args.interval.to_string()));

    // Store active workers as a JSON string
    if !args.active_workers.is_empty() {
        md.push((
            "selective_probing_worker_ids".to_string(),
            serde_json::to_string(&args.active_workers).unwrap_or_default(),
        ));
    }

    let worker_hostnames: Vec<&String> = args.all_workers.right_values().collect();
    md.push((
        "connected_workers".to_string(),
        serde_json::to_string(&worker_hostnames).unwrap_or_default(),
    ));
    md.push((
        "connected_workers_count".to_string(),
        args.all_workers.len().to_string(),
    ));

    if args.is_config && !args.configurations.is_empty() {
        let config_str = args
            .configurations
            .iter()
            .map(|c| {
                format!(
                    "Worker: {}, SrcIP: {}, SrcPort: {}, DstPort: {}",
                    if c.worker_id == u32::MAX {
                        "ALL".to_string()
                    } else {
                        worker_map
                            .get_by_left(&c.worker_id)
                            .unwrap_or(&String::from("Unknown"))
                            .to_string()
                    },
                    c.origin
                        .as_ref()
                        .and_then(|o| o.src)
                        .map_or("N/A".to_string(), |s| s.to_string()),
                    c.origin.as_ref().map_or(0, |o| o.sport),
                    c.origin.as_ref().map_or(0, |o| o.dport)
                )
            })
            .collect::<Vec<_>>();

        md.push((
            "configurations".to_string(),
            serde_json::to_string(&config_str).unwrap_or_default(),
        ));
    }

    md
}

const BATCH_SIZE: usize = 1024;

/// Represents a row of data in the Parquet file format.
/// Fields used depend on the measurement type and configuration.
struct ParquetDataRow {
    /// Hostname of the probe receiver.
    rx: Option<String>,
    /// UNIX timestamp in nanoseconds when the reply was received.
    rx_time: Option<u64>,
    /// Source address of the reply (as a string).
    addr: Option<String>,
    /// Time-to-live (TTL) value of the reply.
    ttl: Option<u8>,
    /// UNIX timestamp in nanoseconds when the request was sent.
    tx_time: Option<u64>,
    /// Hostname of the probe sender.
    tx: Option<String>,
    /// Round-trip time (RTT) in milliseconds.
    rtt: Option<f64>,
    /// DNS TXT CHAOS record value.
    chaos_data: Option<String>,
    /// Origin ID for multi-origin measurements (source address, ports).
    origin_id: Option<u8>,
}

/// Write results to a Parquet file as they are received from the channel.
/// This function processes the results in batches to optimize writing performance.
///
/// # Arguments
///
/// * `rx` - The receiver channel that receives the results.
///
/// * `config` - The configuration for writing results, including file handle, metadata, and measurement type.
///
/// * `metadata_args` - Arguments for generating metadata, including measurement type, origins, and configurations.
pub fn write_results_parquet(mut rx: UnboundedReceiver<TaskResult>, config: WriteConfig) {
    let schema = build_parquet_schema(config.m_type, config.is_multi_origin, config.is_symmetric);

    // Convert metadata Vec<String> to Parquet's KeyValue format
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
            .build(),
    );

    let mut writer = SerializedFileWriter::new(config.output_file, schema.clone(), props)
        .expect("Failed to create parquet writer");

    // We need the headers to maintain column order during writing
    let headers = get_header(config.m_type, config.is_multi_origin, config.is_symmetric);

    tokio::spawn(async move {
        let mut row_buffer: Vec<ParquetDataRow> = Vec::with_capacity(BATCH_SIZE);

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
            if row_buffer.len() >= BATCH_SIZE {
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

/// Creates a parquet data schema from the headers based on the measurement type and configuration.
fn build_parquet_schema(m_type: u32, is_multi_origin: bool, is_symmetric: bool) -> TypePtr {
    let headers = get_header(m_type, is_multi_origin, is_symmetric);
    let mut fields = Vec::new();

    for &header in &headers {
        let field = match header {
            "rx" | "addr" | "tx" | "chaos_data" => {
                SchemaType::primitive_type_builder(header, parquet::basic::Type::BYTE_ARRAY)
                    .with_repetition(Repetition::OPTIONAL)
                    .with_logical_type(Some(parquet::basic::LogicalType::String))
                    .build()
                    .unwrap()
            }
            "rx_time" | "tx_time" => {
                SchemaType::primitive_type_builder(header, parquet::basic::Type::INT64)
                    .with_repetition(Repetition::OPTIONAL)
                    .with_logical_type(Some(LogicalType::Integer {
                        bit_width: 64,
                        is_signed: false,
                    })) // u64
                    .build()
                    .unwrap()
            }
            "ttl" | "origin_id" => {
                SchemaType::primitive_type_builder(header, parquet::basic::Type::INT32)
                    .with_repetition(Repetition::OPTIONAL)
                    .with_logical_type(Some(LogicalType::Integer {
                        bit_width: 8,
                        is_signed: false,
                    })) // u8
                    .build()
                    .unwrap()
            }
            "rtt" => SchemaType::primitive_type_builder(header, parquet::basic::Type::DOUBLE)
                .with_repetition(Repetition::OPTIONAL)
                .build()
                .unwrap(),
            _ => panic!("Unknown header column: {}", header),
        };
        fields.push(Arc::new(field));
    }

    Arc::new(
        SchemaType::group_type_builder("schema")
            .with_fields(fields)
            .build()
            .unwrap(),
    )
}

/// Converts a Reply message into a ParquetDataRow for writing to a Parquet file.
fn reply_to_parquet_row(
    result: Reply,
    rx_worker_id: u32,
    m_type: u8,
    is_symmetric: bool,
    worker_map: &BiHashMap<u32, String>,
) -> ParquetDataRow {
    let mut row = ParquetDataRow {
        rx: worker_map.get_by_left(&rx_worker_id).cloned(),
        rx_time: Some(result.rx_time),
        addr: result.src.map(|s| s.to_string()),
        ttl: Some(result.ttl as u8),
        tx_time: Some(result.tx_time),
        tx: None,
        rtt: None,
        chaos_data: result.chaos,
        origin_id: if result.origin_id != 0 && result.origin_id != u32::MAX {
            Some(result.origin_id as u8)
        } else {
            None
        },
    };

    if is_symmetric {
        row.rtt = Some(calculate_rtt(
            result.rx_time,
            result.tx_time,
            m_type == TCP_ID,
        ));
        row.rx_time = None;
        row.tx_time = None;
    } else {
        row.tx = worker_map.get_by_left(&result.tx_id).cloned();
        if m_type == TCP_ID {
            row.tx_time = None;
        }
    }

    row
}

/// Writes a batch of ParquetDataRow to the Parquet file using the provided writer.
fn write_batch_to_parquet(
    writer: &mut SerializedFileWriter<File>,
    batch: &[ParquetDataRow],
    headers: &[&str],
) -> Result<(), parquet::errors::ParquetError> {
    let mut row_group_writer = writer.next_row_group()?;

    for &header in headers {
        if let Some(mut col_writer) = row_group_writer.next_column()? {
            match header {
                "rx" | "addr" | "tx" | "chaos_data" => {
                    let mut values = Vec::new();
                    let def_levels: Vec<i16> = batch
                        .iter()
                        .map(|row| {
                            let opt_val = match header {
                                "rx" => row.rx.as_ref(),
                                "addr" => row.addr.as_ref(),
                                "tx" => row.tx.as_ref(),
                                "chaos_data" => row.chaos_data.as_ref(),
                                _ => None,
                            };
                            if let Some(val) = opt_val {
                                values.push(ByteArray::from(val.as_str()));
                                1 // 1 means the value is defined (not NULL)
                            } else {
                                0 // 0 means the value is NULL
                            }
                        })
                        .collect();
                    col_writer
                        .typed::<parquet::data_type::ByteArrayType>()
                        .write_batch(&values, Some(&def_levels), None)?;
                }
                "rx_time" | "tx_time" => {
                    let mut values = Vec::new();
                    let def_levels: Vec<i16> = batch
                        .iter()
                        .map(|row| {
                            let opt_val = match header {
                                "rx_time" => row.rx_time,
                                "tx_time" => row.tx_time,
                                _ => None,
                            };
                            if let Some(val) = opt_val {
                                values.push(val as i64);
                                1
                            } else {
                                0
                            }
                        })
                        .collect();
                    col_writer.typed::<Int64Type>().write_batch(
                        &values,
                        Some(&def_levels),
                        None,
                    )?;
                }
                "ttl" | "origin_id" => {
                    let mut values = Vec::new();
                    let def_levels: Vec<i16> = batch
                        .iter()
                        .map(|row| {
                            let opt_val = match header {
                                "ttl" => row.ttl,
                                "origin_id" => row.origin_id,
                                _ => None,
                            };
                            if let Some(val) = opt_val {
                                values.push(val as i32);
                                1
                            } else {
                                0
                            }
                        })
                        .collect();
                    col_writer.typed::<Int32Type>().write_batch(
                        &values,
                        Some(&def_levels),
                        None,
                    )?;
                }
                "rtt" => {
                    let mut values = Vec::new();
                    let def_levels: Vec<i16> = batch
                        .iter()
                        .map(|row| {
                            if let Some(val) = row.rtt {
                                values.push(val);
                                1 // 1 means the value is defined (not NULL)
                            } else {
                                0 // 0 means the value is NULL
                            }
                        })
                        .collect();
                    col_writer.typed::<DoubleType>().write_batch(
                        &values,
                        Some(&def_levels),
                        None,
                    )?;
                }
                _ => {}
            }
            col_writer.close()?;
        }
    }
    row_group_writer.close()?;
    Ok(())
}

use crate::cli::writer::{calculate_rtt, get_header, MetadataArgs, WriteConfig};
use crate::custom_module::manycastr::reply::ReplyData;
use crate::custom_module::manycastr::{MeasurementReply, ReplyBatch};
use crate::{ALL_WORKERS, TCP_ID};
use bimap::BiHashMap;
use parquet::basic::{Compression as ParquetCompression, LogicalType, Repetition};
use parquet::data_type::{ByteArray, DoubleType, Int32Type, Int64Type};
use parquet::file::properties::WriterProperties;
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::types::{Type as SchemaType, TypePtr};
use std::fs::File;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;

const ROW_BUFFER_CAPACITY: usize = 50_000; // Number of rows to buffer before writing (impacts RAM usage)
const MAX_ROW_GROUP_SIZE_BYTES: usize = 256 * 1024 * 1024; // 256 MB

/// Write results to a Parquet file as they are received from the channel.
/// This function processes the results in batches to optimize writing performance.
///
/// # Arguments
/// * `rx` - The receiver channel that receives the results.
/// * `config` - The configuration for writing results, including file handle, metadata, and measurement type.
pub fn write_results_parquet(mut rx: UnboundedReceiver<ReplyBatch>, config: WriteConfig) {
    let headers = get_header(
        config.m_type,
        config.is_multi_origin,
        config.is_symmetric,
        config.is_traceroute,
        config.is_record,
        config.is_verfploeter,
    );
    // TODO implement parquet writer for TraceResults
    let schema = build_parquet_schema(headers);

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
        config.is_verfploeter,
    );

    tokio::spawn(async move {
        let mut row_buffer: Vec<ParquetDataRow> = Vec::with_capacity(ROW_BUFFER_CAPACITY);

        while let Some(task_result) = rx.recv().await {
            if task_result == ReplyBatch::default() {
                break; // End of stream
            }

            let rx_id = task_result.rx_id;
            for reply in task_result.results {
                let Some(ReplyData::Measurement(measurement)) = reply.reply_data else {
                    panic!("Unexpected measurement data")
                };

                let parquet_row = reply_to_parquet_row(
                    measurement,
                    rx_id,
                    config.m_type,
                    config.is_symmetric,
                    config.is_verfploeter,
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

/// Returns a vector of key-value pairs containing the metadata of the measurement.
pub fn get_parquet_metadata(
    args: MetadataArgs<'_>,
    worker_map: &BiHashMap<u32, String>,
) -> Vec<(String, String)> {
    let mut md = Vec::new();

    if args.is_verfploeter {
        md.push(("measurement_style".to_string(), "Verfploeter".to_string()));
    } else if args.is_latency {
        md.push((
            "measurement_style".to_string(),
            "Anycast-latency".to_string(),
        ));
    } else if args.is_responsive {
        md.push((
            "measurement_style".to_string(),
            "LACeS-Responsive-mode".to_string(),
        ));
    } else {
        md.push(("measurement_style".to_string(), "LACeS-mode".to_string()));
    }

    md.push(("hitlist_path".to_string(), args.hitlist.to_string()));
    md.push(("hitlist_shuffled".to_string(), args.is_shuffle.to_string()));
    md.push(("measurement_type".to_string(), args.m_type_str));
    // Store numbers without separators for easier parsing later
    md.push((
        "probing_rate_pps".to_string(),
        args.probing_rate.to_string(),
    ));
    md.push(("worker_interval_ms".to_string(), args.interval.to_string()));

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
                    if c.worker_id == ALL_WORKERS {
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

/// Represents a row of data in the Parquet file format.
/// Fields used depend on the measurement type and configuration.
pub struct ParquetDataRow {
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

/// Converts a Result message into a ParquetDataRow for writing to a Parquet file.
fn reply_to_parquet_row(
    result: MeasurementReply,
    rx_worker_id: u32,
    m_type: u8,
    is_latency: bool,
    is_verfploeter: bool,
    worker_map: &BiHashMap<u32, String>,
) -> ParquetDataRow {
    let mut row = ParquetDataRow {
        rx: worker_map.get_by_left(&rx_worker_id).cloned(),
        rx_time: None,
        addr: result.src.map(|s| s.to_string()),
        ttl: Some(result.ttl as u8),
        tx_time: None,
        tx: None,
        rtt: None,
        chaos_data: result.chaos,
        origin_id: if result.origin_id != 0 && result.origin_id != u32::MAX {
            Some(result.origin_id as u8)
        } else {
            None
        },
    };

    if is_latency {
        row.rtt = Some(calculate_rtt(
            result.rx_time,
            result.tx_time,
            m_type == TCP_ID,
            false
        ));
    } else if is_verfploeter {
        // no additional fields
    } else {
        row.tx = worker_map.get_by_left(&result.tx_id).cloned();
        row.rx_time = Some(result.rx_time);
        row.tx_time = Some(result.tx_time);
    }

    row
}

/// Creates a parquet data schema from the headers based on the measurement type and configuration.
///
/// # Arguments
/// * `headers` - Used headers (based on measurement type)
pub fn build_parquet_schema(headers: Vec<&str>) -> TypePtr {
    let mut fields = Vec::new();

    for &header in &headers {
        let field = match header {
            "rx" | "addr" | "tx" | "chaos_data" => {
                SchemaType::primitive_type_builder(header, parquet::basic::Type::BYTE_ARRAY)
                    .with_repetition(Repetition::OPTIONAL)
                    .with_logical_type(Some(LogicalType::String))
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
            _ => panic!("Unknown header column: {header}"),
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

/// Writes a batch of ParquetDataRow to the Parquet file using the provided writer.
pub fn write_batch_to_parquet(
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

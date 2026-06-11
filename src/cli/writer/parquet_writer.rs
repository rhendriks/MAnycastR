use crate::cli::writer::{MetadataArgs, WriteConfig, get_header};
use crate::custom_module::manycastr::reply::ReplyData;
use crate::custom_module::manycastr::{MeasurementReply, MeasurementType, ReplyBatch, TraceReply};
use crate::{ALL_WORKERS, SINGLE_ORIGIN};
use bimap::BiHashMap;
use parquet::basic::{Compression as ParquetCompression, LogicalType, Repetition};
use parquet::data_type::{ByteArray, FixedLenByteArray, FloatType, Int32Type};
use parquet::file::properties::WriterProperties;
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::types::{Type as SchemaType, TypePtr};
use std::fs::File;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;

const ROW_BUFFER_CAPACITY: usize = 50_000; // Number of rows to buffer before writing (impacts RAM usage)
const MAX_ROW_GROUP_ROW_COUNT: usize = 1_000_000;
// TODO should we order each buffer by IP for better compression?

/// Write results to a Parquet file as they are received from the channel.
/// This function processes the results in batches to optimize writing performance.
///
/// # Arguments
/// * `rx` - The receiver channel that receives the results.
/// * `config` - The configuration for writing results, including file handle, metadata, and measurement type.
pub fn write_results_parquet(mut rx: UnboundedReceiver<ReplyBatch>, config: WriteConfig) {
    let headers = get_header(
        config.is_chaos,
        config.is_multi_origin,
        config.is_record,
        config.m_type,
    );
    let schema = build_parquet_schema(headers.clone());

    // Get metadata key-value pairs for the Parquet file
    let key_value_tuples = get_parquet_metadata(config.metadata_args, &config.worker_map);

    // Configure writer properties, including compression and metadata
    let key_value_metadata: Vec<parquet::file::metadata::KeyValue> = key_value_tuples
        .into_iter()
        .map(|(key, value)| parquet::file::metadata::KeyValue::new(key, value))
        .collect();

    let props = Arc::new(
        WriterProperties::builder()
            .set_compression(ParquetCompression::ZSTD(Default::default()))
            .set_key_value_metadata(Some(key_value_metadata)) // Use the clean metadata
            .set_max_row_group_row_count(Some(MAX_ROW_GROUP_ROW_COUNT))
            .build(),
    );

    let mut writer = SerializedFileWriter::new(config.output_file, schema.clone(), props)
        .expect("Failed to create parquet writer");

    tokio::spawn(async move {
        let mut row_buffer: Vec<ParquetDataRow> = Vec::with_capacity(ROW_BUFFER_CAPACITY);

        while let Some(task_result) = rx.recv().await {
            if task_result == ReplyBatch::default() {
                break; // End of stream
            }

            let rx_id = task_result.rx_id;
            let origin_id = task_result.origin_id;
            for reply in task_result.results {
                let parquet_row = match reply.reply_data {
                    Some(ReplyData::Measurement(m_reply)) => measurement_reply_to_parquet_row(
                        m_reply,
                        rx_id,
                        config.m_type,
                        &config.worker_map,
                        origin_id,
                    ),
                    Some(ReplyData::Trace(trace_reply)) => {
                        trace_reply_to_parquet_row(trace_reply, rx_id, &config.worker_map)
                    }
                    _ => panic!("Unexpected reply data"),
                };
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

    md.push((
        "measurement_type".to_string(),
        args.m_type.as_str().to_string(),
    ));

    if args.is_responsive {
        md.push(("responsive_mode".to_string(), "true".to_string()));
    }

    md.push(("hitlist_path".to_string(), args.hitlist.to_string()));
    md.push(("hitlist_shuffled".to_string(), args.is_shuffle.to_string()));
    md.push(("probing_rate".to_string(), args.probing_rate.to_string()));
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

    let config_str = args
        .configurations
        .iter()
        .map(|c| {
            format!(
                "Worker: {}, Origin ID: {}, src IP: {}, src port: {}, dst port: {}, protocol: {}",
                if c.worker_id == ALL_WORKERS {
                    "ALL".to_string()
                } else {
                    worker_map
                        .get_by_left(&c.worker_id)
                        .unwrap_or(&String::from("Unknown"))
                        .to_string()
                },
                c.origin.as_ref().map_or(0, |o| o.origin_id),
                c.origin
                    .as_ref()
                    .and_then(|o| o.src)
                    .map_or("N/A".to_string(), |s| s.to_string()),
                c.origin.as_ref().map_or(0, |o| o.sport),
                c.origin.as_ref().map_or(0, |o| o.dport),
                c.origin
                    .as_ref()
                    .map_or("N/A".to_string(), |o| o.p_type().to_string())
            )
        })
        .collect::<Vec<_>>();

    md.push((
        "configurations".to_string(),
        serde_json::to_string(&config_str).unwrap_or_default(),
    ));

    md
}

/// Represents a row of data in the Parquet file format.
/// Fields used depend on the measurement type and configuration.
pub struct ParquetDataRow {
    /// Hostname of the probe receiver.
    rx: Option<String>,
    /// Source address of the reply as 16-byte IPv4-mapped-IPv6 (RFC 4291).
    addr: Option<[u8; 16]>,
    /// Time-to-live (TTL) value of the reply.
    ttl: Option<u8>,
    /// Hostname of the probe sender.
    tx: Option<String>,
    /// Round-trip time in milliseconds, computed on the worker (a signed offset in LACeS mode).
    rtt: Option<f32>,
    /// DNS TXT CHAOS record value.
    chaos_data: Option<String>,
    /// Origin ID for multi-origin measurements (source address, ports).
    origin_id: Option<u8>,
    /// Traceroute: destination address of the trace as 16-byte IPv4-mapped-IPv6 (RFC 4291).
    trace_dst: Option<[u8; 16]>,
    /// Traceroute: TTL value used to trigger this reply.
    hop_count: Option<u8>,
}

/// Converts a MeasurementReply into a ParquetDataRow for writing to a Parquet file.
fn measurement_reply_to_parquet_row(
    result: MeasurementReply,
    rx_worker_id: u32,
    m_type: MeasurementType,
    worker_map: &BiHashMap<u32, String>,
    origin_id: u32,
) -> ParquetDataRow {
    let mut row = ParquetDataRow {
        rx: worker_map.get_by_left(&rx_worker_id).cloned(),
        addr: result.src.map(|s| s.to_ipv6_mapped_bytes()),
        ttl: Some(result.ttl as u8),
        tx: None,
        rtt: None,
        chaos_data: result.chaos,
        origin_id: (origin_id != SINGLE_ORIGIN).then_some(origin_id as u8),
        trace_dst: None,
        hop_count: None,
    };

    match m_type {
        MeasurementType::AnycastLatency | MeasurementType::UnicastLatency => {
            row.rtt = Some(result.rtt);
        }
        MeasurementType::Catchment => {
            // Catchment mapping is minimal (rx, addr, ttl)
        }
        MeasurementType::AnycastTraceroute => {
            panic!("Received MeasurementReply during a traceroute measurement")
        }
        MeasurementType::Laces => {
            row.tx = worker_map.get_by_left(&result.tx_id).cloned();
            row.rtt = Some(result.rtt);
        }
    }

    row
}

/// Converts a TraceReply into a ParquetDataRow for writing to a Parquet file.
fn trace_reply_to_parquet_row(
    reply: TraceReply,
    rx_worker_id: u32,
    worker_map: &BiHashMap<u32, String>,
) -> ParquetDataRow {
    // Unresponsive hops have no calculated RTT
    let rtt = if reply.hop_addr.is_some() {
        Some(reply.rtt)
    } else {
        None
    };

    ParquetDataRow {
        rx: worker_map.get_by_left(&rx_worker_id).cloned(),
        addr: reply.hop_addr.map(|a| a.to_ipv6_mapped_bytes()),
        ttl: Some(reply.ttl as u8),
        tx: worker_map.get_by_left(&reply.tx_id).cloned(),
        rtt,
        chaos_data: None,
        origin_id: None,
        trace_dst: reply.trace_dst.map(|a| a.to_ipv6_mapped_bytes()),
        hop_count: Some(reply.hop_count as u8),
    }
}

/// Creates a parquet data schema from the headers based on the measurement type and configuration.
///
/// # Arguments
/// * `headers` - Used headers (based on measurement type)
pub fn build_parquet_schema(headers: Vec<&str>) -> TypePtr {
    let mut fields = Vec::new();

    for &header in &headers {
        let field = match header {
            "rx" | "tx" => {
                SchemaType::primitive_type_builder(header, parquet::basic::Type::BYTE_ARRAY)
                    .with_repetition(Repetition::OPTIONAL)
                    .with_logical_type(Some(LogicalType::Enum))
                    .build()
                    .unwrap()
            }
            "chaos_data" => {
                SchemaType::primitive_type_builder(header, parquet::basic::Type::BYTE_ARRAY)
                    .with_repetition(Repetition::OPTIONAL)
                    .with_logical_type(Some(LogicalType::String))
                    .build()
                    .unwrap()
            }
            "addr" | "trace_dst" => SchemaType::primitive_type_builder(
                header,
                parquet::basic::Type::FIXED_LEN_BYTE_ARRAY,
            )
            .with_repetition(Repetition::OPTIONAL)
            .with_length(16)
            .build()
            .unwrap(),
            "ttl" | "origin_id" | "hop_count" => {
                SchemaType::primitive_type_builder(header, parquet::basic::Type::INT32)
                    .with_repetition(Repetition::OPTIONAL)
                    .with_logical_type(Some(LogicalType::integer(8, false)))
                    .build()
                    .unwrap()
            }
            "rtt" => SchemaType::primitive_type_builder(header, parquet::basic::Type::FLOAT)
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
                "rx" | "tx" | "chaos_data" => {
                    let mut values = Vec::with_capacity(batch.len());
                    let def_levels: Vec<i16> = batch
                        .iter()
                        .map(|row| {
                            let opt_val = match header {
                                "rx" => row.rx.as_ref(),
                                "tx" => row.tx.as_ref(),
                                "chaos_data" => row.chaos_data.as_ref(),
                                _ => None,
                            };
                            if let Some(val) = opt_val {
                                values.push(ByteArray::from(val.as_str()));
                                1
                            } else {
                                0
                            }
                        })
                        .collect();
                    col_writer
                        .typed::<parquet::data_type::ByteArrayType>()
                        .write_batch(&values, Some(&def_levels), None)?;
                }
                "addr" | "trace_dst" => {
                    let mut values: Vec<FixedLenByteArray> = Vec::with_capacity(batch.len());
                    let def_levels: Vec<i16> = batch
                        .iter()
                        .map(|row| {
                            let opt_val = match header {
                                "addr" => row.addr.as_ref(),
                                "trace_dst" => row.trace_dst.as_ref(),
                                _ => None,
                            };
                            if let Some(val) = opt_val {
                                values.push(ByteArray::from(val.as_slice()).into());
                                1
                            } else {
                                0
                            }
                        })
                        .collect();
                    col_writer
                        .typed::<parquet::data_type::FixedLenByteArrayType>()
                        .write_batch(&values, Some(&def_levels), None)?;
                }
                "ttl" | "origin_id" | "hop_count" => {
                    let mut values = Vec::with_capacity(batch.len());
                    let def_levels: Vec<i16> = batch
                        .iter()
                        .map(|row| {
                            let opt_val: Option<u8> = match header {
                                "ttl" => row.ttl,
                                "origin_id" => row.origin_id,
                                "hop_count" => row.hop_count,
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
                    let mut values = Vec::with_capacity(batch.len());
                    let def_levels: Vec<i16> = batch
                        .iter()
                        .map(|row| {
                            if let Some(val) = row.rtt {
                                values.push(val);
                                1
                            } else {
                                0
                            }
                        })
                        .collect();
                    col_writer.typed::<FloatType>().write_batch(
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

use std::fs::File;
use std::io;
use std::io::Write;

use bimap::BiHashMap;
use csv::Writer;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::cli::writer::csv_writer::get_csv_metadata;
use crate::cli::writer::laces_row::get_laces_row;
use crate::cli::writer::latency_row::get_latency_row;
use crate::cli::writer::trace_row::get_trace_row;
use crate::cli::writer::verfploeter_row::get_verfploeter_csv_row;
use crate::custom_module;
use crate::custom_module::manycastr::reply::ReplyData;
use crate::custom_module::manycastr::{MeasurementType, ProtocolType};
use custom_module::manycastr::{Configuration, Reply, ReplyBatch};
use flate2::write::GzEncoder;
use flate2::Compression;
use log::error;
use std::io::BufWriter;

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
    /// Protocol used for the measurement
    pub p_type: ProtocolType,
    /// Measurement type
    pub m_type: MeasurementType,
    /// Indicates whether the measurement involves multiple origins
    pub is_multi_origin: bool,
    /// A bidirectional map used to convert worker IDs (u16) to their corresponding hostnames (String).
    pub worker_map: BiHashMap<u32, String>,
    /// Indicate whether Record Route is used
    pub is_record: bool,
}

/// Holds all the arguments required to metadata for the output file.
pub struct MetadataArgs<'a> {
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
    /// Whether this is a responsiveness-based measurement.
    pub is_responsive: bool,
    /// Measurement type
    pub m_type: MeasurementType,
    /// Protocol type
    pub p_type: ProtocolType,
}

struct DualWriter<W1: Write, W2: Write> {
    file: Writer<W1>,
    cli: Option<Writer<W2>>,
}

impl<W1: Write, W2: Write> DualWriter<W1, W2> {
    fn write_record<I, T>(&mut self, record: I) -> csv::Result<()>
    where
        I: IntoIterator<Item = T> + Clone,
        T: AsRef<[u8]>,
    {
        if let Some(ref mut cli) = self.cli {
            cli.write_record(record.clone())?;
        }
        self.file.write_record(record)?;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()?;
        if let Some(ref mut cli) = self.cli {
            cli.flush()?;
        }
        Ok(())
    }
}

/// Writes the results to a file (and optionally to the command-line)
///
/// # Arguments
/// * `rx` - The receiver channel that receives the results
/// * `config` - The configuration for writing results, including file handle, metadata, and measurement type
pub fn write_results_csv(mut rx: UnboundedReceiver<ReplyBatch>, config: WriteConfig) {
    // Create writers (file writer and optional CLI writer)
    let buffered_file_writer = BufWriter::new(config.output_file);
    let mut gz_encoder = GzEncoder::new(buffered_file_writer, Compression::default());

    // Write metadata to file
    let md_lines = get_csv_metadata(config.metadata_args, &config.worker_map);
    for line in md_lines {
        if let Err(e) = writeln!(gz_encoder, "{line}") {
            error!("Failed to write metadata line to Gzip stream: {e}");
        }
    }

    let mut dual_wtr = DualWriter {
        file: Writer::from_writer(gz_encoder),
        cli: config
            .print_to_cli
            .then(|| Writer::from_writer(io::stdout())),
    };

    // Write header
    let header = get_header(
        config.p_type == ProtocolType::ChaosDns,
        config.is_multi_origin,
        config.is_record,
        config.m_type,
    );
    dual_wtr
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
                        ReplyData::Measurement(reply) => match config.m_type {
                            MeasurementType::UnicastLatency | MeasurementType::AnycastLatency => {
                                get_latency_row(
                                    reply,
                                    &rx_id,
                                    &config.worker_map,
                                    config.p_type == ProtocolType::Tcp,
                                )
                            }
                            MeasurementType::Verfploeter => {
                                get_verfploeter_csv_row(reply, &rx_id, &config.worker_map)
                            }
                            MeasurementType::Laces => get_laces_row(
                                reply,
                                &rx_id,
                                config.p_type == ProtocolType::Tcp,
                                &config.worker_map,
                            ),
                            MeasurementType::AnycastTraceroute => {
                                panic!("Received regular reply during a traceroute measurement")
                            }
                        },
                        ReplyData::Trace(reply) => get_trace_row(reply, &rx_id, &config.worker_map),
                        ReplyData::Discovery(_) => panic!("Discovery result forwarded to CLI"),
                    },
                    None => {
                        panic!("Reply contained no result data!");
                    }
                };
                // Write to command-line
                dual_wtr
                    .write_record(row)
                    .expect("Failed to write record to file");
            }
            dual_wtr.flush().expect("Failed to flush file");
        }
        rx.close();
        dual_wtr.flush().expect("Failed to flush file");
    });
}

/// Creates the appropriate CSV header for the results file (based on the measurement type)
///
/// # Arguments
/// * `is_chaos` - Whether CHAOS queries are sent
/// * `is_multi_origin` - A boolean that determines whether multiple origins are used
/// * `is_record` - Whether Record Route is used
/// * `m_type` - Measurement type performed
pub fn get_header(
    is_chaos: bool,
    is_multi_origin: bool,
    is_record: bool,
    m_type: MeasurementType,
) -> Vec<&'static str> {
    // Determine headers based on measurement type
    let mut header = match m_type {
        MeasurementType::AnycastTraceroute => {
            vec![
                "rx",
                "hop_addr",
                "ttl",
                "tx",
                "trace_dst",
                "hop_count",
                "rtt",
            ]
        }
        MeasurementType::AnycastLatency | MeasurementType::UnicastLatency => {
            vec!["rx", "addr", "ttl", "rtt"]
        }
        MeasurementType::Verfploeter => {
            vec!["rx", "addr", "ttl"]
        }
        MeasurementType::Laces => {
            vec!["rx", "rx_time", "addr", "ttl", "tx_time", "tx"]
        }
    };

    // Optional fields
    if is_chaos {
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

/// Calculate RTT
///
/// # Arguments
/// `rx_time` - receive time (64 bit microseconds EPOCH)
/// `tx_time` - transmit time (64 bit microseconds EPOCH)
/// `is_tcp` - whether it is a TCP encoded timestamp
///
/// # Note
/// TCP timestamps are masked to 21 bits using millisecond EPOCH
pub fn calculate_rtt(rx_time: u64, tx_time: u64, is_tcp: bool, is_traceroute: bool) -> f64 {
    if is_tcp {
        // 21 bit millisecond timestamp (2^21 = 2,097,152)
        const MODULUS: u64 = 1 << 21;
        const MASK: u64 = MODULUS - 1; // 0x1FFFFF
        let rx_time_ms = rx_time / 1_000;
        let rx_21b = rx_time_ms & MASK;
        let tx_21b = tx_time & MASK;
        let rtt_ms = if rx_21b >= tx_21b {
            rx_21b - tx_21b
        } else {
            // wrap-around case
            (rx_21b + MODULUS) - tx_21b
        };

        rtt_ms as f64
    } else if is_traceroute {
        // 14-bit Modulus (2^14 = 16,384)
        const MODULUS: u64 = 1 << 14;
        const MASK: u64 = MODULUS - 1; // 0x3FFF

        let rx_14b = rx_time & MASK;

        let rtt_ms = if rx_14b >= tx_time {
            rx_14b - tx_time
        } else {
            // wrap-around case
            (rx_14b + MODULUS) - tx_time
        };

        rtt_ms as f64
    } else {
        (rx_time - tx_time) as f64 / 1_000.0
    }
}

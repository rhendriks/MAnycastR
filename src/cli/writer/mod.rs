use std::fs::File;
use std::io;
use std::io::Write;

use bimap::BiHashMap;
use csv::Writer;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::cli::writer::catchment_row::get_catchment_csv_row;
use crate::cli::writer::csv_writer::get_csv_metadata;
use crate::cli::writer::laces_row::get_laces_row;
use crate::cli::writer::latency_row::get_latency_row;
use crate::cli::writer::trace_row::get_trace_row;
use crate::custom_module;
use crate::custom_module::manycastr::MeasurementType;
use crate::custom_module::manycastr::reply::ReplyData;
use custom_module::manycastr::{Configuration, Reply, ReplyBatch};
use flate2::Compression;
use flate2::write::GzEncoder;
use log::error;
use std::io::BufWriter;

mod catchment_row;
pub mod csv_writer;
mod laces_row;
mod latency_row;
pub mod parquet_writer;
mod trace_row;

/// Configuration for the results writing process.
pub struct WriteConfig<'a> {
    /// Determines whether the results should also be printed to the command-line interface.
    pub print_to_cli: bool,
    /// The file handle to which the measurement results should be written.
    pub output_file: File,
    /// Metadata for the measurement, to be written at the beginning of the output file.
    pub metadata_args: MetadataArgs<'a>,
    /// Measurement type
    pub m_type: MeasurementType,
    /// Indicates whether the measurement involves multiple origins
    pub is_multi_origin: bool,
    /// A bidirectional map used to convert worker IDs (u16) to their corresponding hostnames (String).
    pub worker_map: BiHashMap<u32, String>,
    /// Indicate whether any Origin is for CHAOS
    pub is_chaos: bool,
}

/// Holds all the arguments required to metadata for the output file.
pub struct MetadataArgs<'a> {
    /// Path to the hitlist used.
    pub hitlist: &'a str,
    /// Number of targets in the hitlist.
    pub hitlist_length: usize,
    /// Whether the hitlist was shuffled.
    pub is_shuffle: bool,
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
    /// Measurement start time (Unix epoch seconds).
    pub start_time: u64,
    /// Record to send CHAOS (TXT) or A/AAAA requests for.
    pub record: Option<&'a str>,
    /// URL encoded in probes (e.g., opt-out link).
    pub url: Option<&'a str>,
    /// Interval between probes from/to the same origin,dst pair (seconds).
    pub probe_interval: u32,
    /// Number of probes sent per origin,dst pair.
    pub number_of_probes: u32,
    /// Whether protocols are tried in order until the target responds.
    pub is_any_protocol: bool,
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
    let header = get_header(config.is_chaos, config.is_multi_origin, config.m_type);
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
            let origin_id = task_result.origin_id;

            for result in results {
                let row = match result.reply_data {
                    Some(data) => match data {
                        ReplyData::Measurement(reply) => match config.m_type {
                            MeasurementType::AnycastLatency => {
                                get_latency_row(reply, &rx_id, &config.worker_map, origin_id)
                            }
                            MeasurementType::Catchment => {
                                get_catchment_csv_row(reply, &rx_id, &config.worker_map, origin_id)
                            }
                            MeasurementType::Laces | MeasurementType::Feed => {
                                get_laces_row(reply, &rx_id, &config.worker_map, origin_id)
                            }
                            MeasurementType::AnycastTraceroute
                            | MeasurementType::Tracemap
                            | MeasurementType::FeedTrace => {
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
/// * `m_type` - Measurement type performed
pub fn get_header(
    is_chaos: bool,
    is_multi_origin: bool,
    m_type: MeasurementType,
) -> Vec<&'static str> {
    // Determine headers based on measurement type
    let mut header = match m_type {
        MeasurementType::AnycastTraceroute | MeasurementType::Tracemap => {
            vec!["rx", "addr", "ttl", "tx", "trace_dst", "hop_count", "rtt"]
        }
        MeasurementType::FeedTrace => {
            vec!["rx", "addr", "ttl", "tx", "trace_dst", "probe_ttl", "rtt"]
        }
        MeasurementType::AnycastLatency => {
            vec!["rx", "addr", "ttl", "rtt"]
        }
        MeasurementType::Catchment => {
            vec!["rx", "addr", "ttl"]
        }
        MeasurementType::Laces | MeasurementType::Feed => {
            // CHAOS replies carry no transmit timestamp, so there is no RTT to report
            if is_chaos {
                vec!["rx", "addr", "ttl", "tx"]
            } else {
                vec!["rx", "addr", "ttl", "tx", "rtt"]
            }
        }
    };

    // Optional fields
    if is_chaos {
        header.push("chaos_data");
    }
    if is_multi_origin {
        header.push("origin_id");
    }

    header
}

/// Format RTT (milliseconds) as a three-decimal string (for .csv compression)
pub fn format_rtt(rtt: f32) -> String {
    format!("{rtt:.3}")
}

use std::fs::File;
use std::io;
use std::io::Write;

use bimap::BiHashMap;
use csv::Writer;
use tokio::sync::mpsc::UnboundedReceiver;

use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::BufWriter;

use custom_module::manycastr::{Configuration, Reply, TaskResult};
use custom_module::Separated;

use crate::{custom_module, CHAOS_ID, TCP_ID};

/// Configuration for the results writing process.
///
/// This struct bundles all the necessary parameters for `write_results`
/// to determine where and how to output measurement results,
/// including formatting options and contextual metadata.
pub struct WriteConfig {
    /// Determines whether the results should also be printed to the command-line interface.
    pub print_to_cli: bool,
    /// The file handle to which the measurement results should be written.
    pub output_file: File,
    /// Metadata for the measurement, to be written at the beginning of the output file.
    pub metadata_lines: Vec<String>,
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
    /// Start of measurement.
    pub m_start: String,
    /// Expected duration of the measurement in seconds.
    pub expected_duration: f32,
    /// Workers selected to probe.
    pub active_workers: Vec<u32>,
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
    for line in &config.metadata_lines {
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
                    config.m_type,
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
fn get_row(
    result: Reply,
    rx_worker_id: u32,
    m_type: u32,
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
            (result.rx_time - result.tx_time) as f64 / 1_000_000.0
        );
        vec![rx_hostname, reply_src, ttl, rtt]
    } else {
        let tx_hostname = worker_map
            .get_by_left(&tx_id)
            .unwrap_or(&String::from("Unknown"))
            .to_string();

        // TCP anycast does not have tx_time
        if m_type == TCP_ID as u32 {
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

/// Returns a vector of lines containing the metadata of the measurement
///
/// # Arguments
///
/// Variables describing the measurement
pub fn get_metadata(args: MetadataArgs<'_>) -> Vec<String> {
    let mut md_file = Vec::new();
    if args.is_divide {
        md_file.push("# Divide-and-conquer measurement".to_string());
    }
    if args.is_latency {
        md_file.push("# Latency measurement".to_string());
    }
    if args.is_responsive {
        md_file.push("# Responsive measurement".to_string());
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
    md_file.push(format!("# Interval: {}", args.interval));
    md_file.push(format!("# Start measurement: {}", args.m_start));
    md_file.push(format!(
        "# Expected measurement duration (seconds): {:.6}",
        args.expected_duration
    ));
    if !args.active_workers.is_empty() {
        md_file.push(format!(
            "# Selective probing using the following workers: {:?}",
            args.active_workers
        ));
    }
    md_file.push("# Connected workers:".to_string());
    for (id, hostname) in args.all_workers {
        md_file.push(format!("# \t * ID: {:<2}, hostname: {}", id, hostname))
    }

    // Write configurations used for the measurement
    if args.is_config {
        md_file.push("# Configurations:".to_string());
        for configuration in args.configurations {
            let origin = configuration.origin.unwrap();
            let src = origin.src.expect("Invalid source address");
            let worker_id = if configuration.worker_id == u32::MAX {
                "ALL".to_string()
            } else {
                configuration.worker_id.to_string()
            };
            md_file.push(format!(
                "# \t * Worker ID: {:<2}, source IP: {}, source port: {}, destination port: {}",
                worker_id, src, origin.sport, origin.dport
            ));
        }
    }

    md_file
}

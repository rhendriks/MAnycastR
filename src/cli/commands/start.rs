use crate::cli::client::CliClient;
use crate::cli::config::{get_hitlist, parse_configurations};
use crate::cli::utils::validate_path_perms;
use crate::custom_module::manycastr::address::Value::Unicast;
use crate::custom_module::manycastr::{
    Address, Configuration, Empty, Origin, ScheduleMeasurement, TraceOptions,
};
use crate::custom_module::Separated;
use crate::{ALL_ID, ALL_WORKERS, ANY_ID, A_ID, CHAOS_ID, ICMP_ID, TCP_ID};
use bimap::BiHashMap;
use clap::ArgMatches;
use log::{info, warn};
use prettytable::{format, row, Table};

pub struct MeasurementExecutionArgs<'a> {
    /// Determines whether results should be streamed to the command-line interface as they arrive.
    pub is_cli: bool,
    /// Indicates whether the results should be written in Parquet format (default: .csv.gz).
    pub is_parquet: bool,
    /// Specifies whether the list of targets should be shuffled before the measurement begins.
    pub is_shuffle: bool,
    /// The path to the file containing the list of measurement targets (the "hitlist").
    pub hitlist_path: &'a str,
    /// The total number of targets in the hitlist, used for estimating measurement duration.
    pub hitlist_length: usize,
    /// Path to write results to (may include filename and extension).
    pub out_path: String,
    /// Indicates whether the measurement is configuration-based (using a configuration file)
    pub is_config: bool,
    /// A bidirectional map used to resolve worker IDs to their corresponding hostnames.
    pub worker_map: BiHashMap<u32, String>,
    /// Indicates whether the measurement is a traceroute
    pub is_traceroute: bool,
    /// Indicates a Record Route measurement
    pub is_record: bool,
}

/// Handle the start command by parsing arguments and sending a measurement request to the orchestrator.
///
/// # Arguments
///
/// * `matches` - The parsed command-line arguments specific to the start command.
/// * `grpc_client` - A mutable reference to the gRPC client used to communicate with the orchestrator.
/// * `worker_map` - A bidirectional map of worker IDs to hostnames for selective probing.
/// # Returns
/// * `Result<(), Box<dyn std::error::Error>>` - Ok(()) if the measurement was successfully started, or an error if something went wrong.
pub async fn handle(
    matches: &ArgMatches,
    grpc_client: &mut CliClient,
    worker_map: BiHashMap<u32, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Start a MAnycastR measurement
    let is_unicast = matches.get_flag("unicast");
    let is_divide = matches.get_flag("divide");
    let is_responsive = matches.get_flag("responsive");
    let is_latency = matches.get_flag("latency");
    let is_traceroute = matches.get_flag("traceroute");

    // Get optional opt-out URL
    let url = matches.get_one::<String>("url").unwrap().clone();

    // Source IP for the measurement
    let src = if is_unicast {
        Some(Address {
            value: Some(Unicast(Empty {})),
        })
    } else if !matches.contains_id("configuration") {
        matches.get_one::<String>("address").map(Address::from)
    } else {
        None
    };

    // Get the measurement type
    let m_type = match matches.get_one::<String>("type").unwrap().as_str() {
        "icmp" => ICMP_ID,
        "dns" => A_ID,
        "tcp" => TCP_ID,
        "chaos" => CHAOS_ID,
        "any" => ANY_ID,
        "all" => ALL_ID,
        _ => panic!("Invalid measurement type! (can be either ICMP, DNS, TCP, all, or CHAOS)"),
    };

    let is_config = matches.contains_id("configuration");

    // Get the workers that have to send out probes
    let sender_ids: Vec<u32> = matches.get_one::<String>("selective").map_or_else(
        || vec![ALL_WORKERS], // Default: all workers
        |worker_entries_str| {
            worker_entries_str
                .trim_matches(|c| c == '[' || c == ']')
                .split(',')
                .filter_map(|entry_str_untrimmed| {
                    let entry_str = entry_str_untrimmed.trim();
                    if entry_str.is_empty() {
                        return None; // Skip trailing commas
                    }
                    // Try to parse as worker ID
                    if let Ok(id_val) = entry_str.parse::<u32>() {
                        if worker_map.contains_left(&id_val) {
                            Some(id_val)
                        } else {
                            warn!("Worker ID '{entry_str}' is not a known worker.");
                            None
                        }
                    } else if let Some(&found_id) = worker_map.get_by_right(entry_str) {
                        Some(found_id)
                    } else {
                        warn!("'{entry_str}' is not a valid worker ID or known hostname.");
                        None
                    }
                })
                .collect()
        },
    );

    // Read the configuration file
    let configurations = if is_config {
        let conf_file = matches.get_one::<String>("configuration").unwrap();
        parse_configurations(conf_file, &worker_map)
    } else {
        // Obtain port values (read as u16 as is the port header size)
        let sport: u32 = *matches.get_one::<u16>("source port").unwrap() as u32;
        // Default destination port is 53 for DNS, 63853 for all other measurements
        let dport = matches
            .get_one::<u16>("destination port")
            .map(|&port| port as u32)
            .unwrap_or_else(|| {
                if m_type == A_ID || m_type == CHAOS_ID {
                    53
                } else {
                    63853
                }
            });

        // list of worker IDs defined
        sender_ids
            .iter()
            .map(|&worker_id| Configuration {
                worker_id,
                origin: Some(Origin {
                    src,
                    sport,
                    dport,
                    origin_id: 0, // Only one origin
                }),
            })
            .collect()
    };

    // Get the target IP addresses
    let hitlist_path = matches.get_one::<String>("hitlist").unwrap();
    let is_shuffle = matches.get_flag("shuffle");

    let (targets, is_ipv6) = get_hitlist(hitlist_path, &configurations, is_unicast, is_shuffle);

    // Record to request in the DNS query (A/CHAOS)
    let dns_record = if m_type == CHAOS_ID {
        matches
            .get_one::<String>("query")
            .map_or("hostname.bind", |q| q.as_str())
    } else if m_type == A_ID || m_type == ALL_ID {
        matches
            .get_one::<String>("query")
            .map_or("example.org", |q| q.as_str())
    } else {
        ""
    };

    let is_cli = matches.get_flag("stream");
    let is_parquet = matches.get_flag("parquet");
    let is_record = matches.get_flag("record"); // Record Route flag
    let worker_interval = *matches.get_one::<u32>("worker_interval").unwrap();
    let probe_interval = *matches.get_one::<u32>("probe_interval").unwrap();
    let probing_rate = *matches.get_one::<u32>("rate").unwrap();
    let number_of_probes = *matches.get_one::<u32>("number_of_probes").unwrap();
    let t_type = match m_type {
        ICMP_ID => "ICMP",
        A_ID => "DNS/A",
        TCP_ID => "TCP/SYN-ACK",
        CHAOS_ID => "DNS/CHAOS",
        ANY_ID => "Any (ICMP,DNS/A,TCP)",
        ALL_ID => "All (ICMP,DNS/A,TCP)",
        _ => "Unknown",
    };
    let hitlist_length = targets.len();

    // Measurement category (unicast, divide, latency, responsive, traceroute, reverse traceroute, anycast (default))
    let m_cat = if is_unicast {
        "Unicast"
    } else if is_divide {
        "Anycast-divide"
    } else if is_latency {
        "Anycast-latency"
    } else if is_traceroute {
        "Anycast-traceroute"
    } else if is_record {
        "Anycast-Record-Route"
    } else {
        "Anycast"
    };
    let m_cat = if is_responsive {
        format!("{}-responsive", m_cat)
    } else {
        m_cat.to_string()
    };

    info!("[CLI] Performing {m_cat} {t_type} measurement targeting {} addresses, with a rate of {}, and a worker-interval of {worker_interval} seconds",
             hitlist_length.with_separator(),
             probing_rate.with_separator(),
    );

    // Print the origins used
    info!("[CLI] Workers send probes using the following configurations:");
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_titles(row![b->"Worker", b->"ID", b->"Source IP", b->"Source Port", b->"Dest Port"]);

    for config in &configurations {
        if let Some(origin) = &config.origin {
            let (worker_name, worker_id_str) = if config.worker_id == ALL_WORKERS {
                ("All Workers".to_string(), "ALL".to_string())
            } else {
                (
                    worker_map
                        .get_by_left(&config.worker_id)
                        .cloned()
                        .unwrap_or_else(|| "Unknown".to_string()),
                    config.worker_id.to_string(),
                )
            };

            table.add_row(row![
                worker_name,
                worker_id_str,
                origin.src.unwrap().to_string(),
                origin.sport,
                origin.dport
            ]);
        }
    }
    table.printstd();

    // get optional path to write results to
    let path = matches.get_one::<String>("out").unwrap().to_string();
    validate_path_perms(&path)?;

    let trace_options = if is_traceroute {
        Some(TraceOptions {
            max_failures: *matches
                .get_one::<u32>("trace-max-failures")
                .expect("defaulted"),
            max_hops: *matches.get_one::<u32>("trace-max-hops").expect("defaulted"),
            timeout: *matches.get_one::<u32>("trace-timeout").expect("defaulted"),
            initial_hop: *matches
                .get_one::<u32>("trace-initial-hop")
                .expect("defaulted"),
        })
    } else {
        None
    };

    // Create the measurement definition and send it to the orchestrator
    let m_definition = ScheduleMeasurement {
        probing_rate,
        configurations,
        m_type: m_type as u32,
        is_divide,
        worker_interval,
        is_responsive,
        is_latency,
        targets,
        record: dns_record.to_string(),
        url,
        probe_interval,
        number_of_probes,
        is_ipv6,
        is_record,
        trace_options,
    };

    let args = MeasurementExecutionArgs {
        is_cli,
        is_parquet,
        is_shuffle,
        hitlist_path,
        hitlist_length,
        out_path: path,
        is_config,
        worker_map,
        is_traceroute,
        is_record,
    };

    grpc_client
        .do_measurement_to_server(m_definition, args, is_ipv6, is_unicast)
        .await
}

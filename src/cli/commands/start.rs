use bimap::BiHashMap;
use clap::ArgMatches;
use log::{info, warn};
use prettytable::{format, row, Table};
use crate::cli::client::CliClient;
use crate::custom_module::manycastr::{Address, Configuration, Origin, ScheduleMeasurement};
use crate::{ALL_ID, ALL_WORKERS, A_ID, CHAOS_ID, ICMP_ID, TCP_ID};
use crate::cli::config::{get_hitlist, parse_configurations};
use crate::cli::utils::validate_path_perms;
use crate::custom_module::Separated;

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

    /// An optional path to a file where the final measurement results should be saved.
    /// If `None`, results will be written to the current directory with a default naming convention.
    pub out_path: Option<&'a String>,

    /// Indicates whether the measurement is configuration-based (using a configuration file)
    pub is_config: bool,

    /// A bidirectional map used to resolve worker IDs to their corresponding hostnames.
    pub worker_map: BiHashMap<u32, String>,

    /// Indicates whether the measurement is a traceroute
    pub is_traceroute: bool,
}

/// Handle the start command by parsing arguments and sending a measurement request to the orchestrator.
///
/// # Arguments
///
/// * `matches` - The parsed command-line arguments specific to the start command.
/// * `cli_client` - A mutable reference to the GRPC client used to communicate with the orchestrator.
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
    let mut is_latency = matches.get_flag("latency");
    let is_traceroute = matches.get_flag("traceroute");

    if is_responsive && is_divide {
        panic!("Incompatible flags: Responsive mode cannot be combined with divide-and-conquer measurements.");
    } else if is_latency && (is_divide || is_responsive) {
        panic!("Incompatible flags: Latency mode cannot be combined with divide-and-conquer or responsive measurements.");
    } else if is_unicast && is_latency {
        is_latency = false; // Unicast mode is latency by design
    }

    // Get optional opt-out URL
    let url = matches.get_one::<String>("url").unwrap().clone();

    // Source IP for the measurement
    let src = matches.get_one::<String>("address").map(Address::from);

    // Get the measurement type
    let m_type = match matches
        .get_one::<String>("type")
        .unwrap()
        .to_lowercase()
        .as_str()
    {
        "icmp" => ICMP_ID,
        "dns" => A_ID,
        "tcp" => TCP_ID,
        "chaos" => CHAOS_ID,
        "all" => ALL_ID,
        _ => panic!("Invalid measurement type! (can be either ICMP, DNS, TCP, all, or CHAOS)"),
    };

    // TODO TCP and --latency are currently broken
    if is_latency && m_type == TCP_ID {
        panic!("TCP measurements are not supported in latency mode!");
    }

    // Temporarily broken
    if is_responsive && is_unicast && m_type == TCP_ID {
        panic!("Responsive mode not supported for unicast TCP measurements");
    }

    let is_config = matches.contains_id("configuration");

    // Get the workers that have to send out probes TODO convert this into configurations
    let sender_ids: Vec<u32> = matches.get_one::<String>("selective").map_or_else(
        || {
            info!(
                "[CLI] Probes will be sent out from all ({}) workers",
                worker_map.len()
            );
            Vec::new()
        },
        |worker_entries_str| {
            info!("[CLI] Selective probing using specified workers...");
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
                            let hostname = worker_map.get_by_left(&id_val).unwrap();
                            info!("[CLI]\t * ID: {id_val}, Hostname: {hostname}");
                            Some(id_val)
                        } else {
                            warn!("Worker ID '{entry_str}' is not a known worker.");
                            None
                        }
                    } else if let Some(&found_id) = worker_map.get_by_right(entry_str) {
                        let hostname = worker_map.get_by_left(&found_id).unwrap();
                        info!("[CLI]\t * ID: {found_id}, Hostname: {hostname}");
                        Some(found_id)
                    } else {
                        warn!("'{entry_str}' is not a valid worker ID or known hostname.");
                        None
                    }
                })
                .collect()
        },
    );

    // Read the configuration file (unnecessary for unicast)
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

        if sender_ids.is_empty() {
            // All workers
            vec![Configuration {
                worker_id: u32::MAX, // All clients
                origin: Some(Origin {
                    src,
                    sport,
                    dport,
                    origin_id: 0, // Only one origin
                }),
            }]
        } else {
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
        }
    };

    // There must be a defined anycast source address, configuration, or unicast flag
    if src.is_none() && !is_config && !is_unicast {
        panic!("No source address or configuration file provided!");
    }

    // Get the target IP addresses
    let hitlist_path = matches.get_one::<String>("IP_FILE").unwrap();
    let is_shuffle = matches.get_flag("shuffle");

    let (targets, is_ipv6) = get_hitlist(hitlist_path, &configurations, is_unicast, is_shuffle);

    // CHAOS value to send in the DNS query
    let dns_record = if m_type == CHAOS_ID {
        // get CHAOS query
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

    // Check for command-line option that determines whether to stream to CLI
    let is_cli = matches.get_flag("stream");

    // Check for command-line option that determines whether to write results in Parquet format
    let is_parquet = matches.get_flag("parquet");

    if is_cli && is_parquet {
        panic!("Cannot stream results to CLI and write in Parquet format at the same time!");
    }

    // --latency and --divide send single probes to each address, so no worker interval is needed
    let worker_interval = if is_latency || is_divide {
        0
    } else {
        *matches.get_one::<u32>("worker_interval").unwrap()
    };
    let probe_interval = *matches.get_one::<u32>("probe_interval").unwrap();
    let probing_rate = *matches.get_one::<u32>("rate").unwrap();
    let number_of_probes = *matches.get_one::<u32>("number_of_probes").unwrap();
    let t_type = match m_type {
        ICMP_ID => "ICMP",
        A_ID => "DNS/A",
        TCP_ID => "TCP/SYN-ACK",
        CHAOS_ID => "DNS/CHAOS",
        ALL_ID => "All (ICMP,DNS/A,TCP)",
        _ => "Unknown",
    };
    let hitlist_length = targets.len();

    info!("[CLI] Performing {t_type} measurement targeting {} addresses, with a rate of {}, and a worker-interval of {worker_interval} seconds",
             hitlist_length.with_separator(),
             probing_rate.with_separator(),
    );

    if is_responsive {
        info!("[CLI] Responsive mode enabled");
    }

    if is_latency {
        info!("[CLI] Latency mode enabled");
    }

    // Print the origins used TODO always put origins in the configurations to simplify code
    if is_unicast {
        let unicast_origin = configurations.first().unwrap().origin.unwrap();
        info!(
            "[CLI] Unicast probing with src port {} and dst port {}",
            unicast_origin.sport, unicast_origin.dport
        );
    } else if is_config {
        info!("[CLI] Workers send probes using the following configurations:");
        let mut table = Table::new();
        table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
        table.set_titles(row![b->"Worker", b->"ID", b->"Source IP", b->"Source Port", b->"Dest Port"]);

        for config in &configurations {
            if let Some(origin) = &config.origin {
                let (worker_name, worker_id_str) = if config.worker_id == ALL_WORKERS {
                    ("All Workers".to_string(), "N/A".to_string())
                } else {
                    (
                        worker_map.get_by_left(&config.worker_id).cloned().unwrap_or_else(|| "Unknown".to_string()),
                        config.worker_id.to_string(),
                    )
                };
                let source_ip = origin.src.map_or_else(|| "N/A".to_string(), |addr| addr.to_string());

                table.add_row(row![worker_name, worker_id_str, source_ip, origin.sport, origin.dport]);
            }
        }
        table.printstd();
    } else {
        let anycast_origin = configurations.first().unwrap().origin.unwrap();

        info!(
            "[CLI] Workers probe with source IP: {}, source port: {}, destination port: {}",
            anycast_origin.src.unwrap(),
            anycast_origin.sport,
            anycast_origin.dport
        );
    }

    // get optional path to write results to
    let path = matches.get_one::<String>("out");
    if let Some(value) = validate_path_perms(path) {
        return value;
    }

    // Create the measurement definition and send it to the orchestrator
    let m_definition = ScheduleMeasurement {
        probing_rate,
        configurations,
        m_type: m_type as u32,
        is_unicast,
        is_ipv6,
        is_divide,
        worker_interval,
        is_responsive,
        is_latency,
        targets,
        record: dns_record.to_string(),
        url,
        probe_interval,
        number_of_probes,
        is_traceroute,
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
    };

    grpc_client
        .do_measurement_to_server(m_definition, args)
        .await
}
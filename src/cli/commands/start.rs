use crate::cli::client::CliClient;
use crate::cli::config::{get_hitlist, get_targets, parse_configurations};
use crate::cli::utils::validate_path_perms;
use crate::custom_module::manycastr::address::Value::Unicast;
use crate::custom_module::manycastr::{
    Address, Configuration, Empty, MeasurementType, Origin, ProtocolType, ScheduleMeasurement,
    TraceOptions,
};
use crate::custom_module::Separated;
use crate::{ALL_WORKERS, SINGLE_ORIGIN};
use bimap::BiHashMap;
use clap::ArgMatches;
use log::{error, info, warn};
use prettytable::{format, row, Table};
use std::collections::HashSet;

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
    /// A bidirectional map used to resolve worker IDs to their corresponding hostnames.
    pub worker_map: BiHashMap<u32, String>,
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
    let is_any_protocol = matches.get_flag("any");
    let is_responsive = matches.get_flag("responsive") || is_any_protocol;
    let is_record = matches.get_flag("record");
    let url = matches.get_one::<String>("URL");
    let m_type = MeasurementType::from_str(matches.get_one::<String>("m_type").unwrap())
        .expect("Invalid measurement type");

    let configurations = if let Some(conf_path) = matches.get_one::<String>("configuration") {
        // Use configuration set by the user
        parse_configurations(conf_path, &worker_map)
    } else {
        // Create our own configuration from the arguments
        let src = if m_type == MeasurementType::UnicastLatency {
            Address {
                value: Some(Unicast(Empty {})),
            }
        } else if let Some(anycast_address) = matches.get_one::<String>("address") {
            Address::from(anycast_address)
        } else {
            let msg = "[CLI] You must provide --address or --configuration unless --m_type is set to 'unicast'.";
            error!("{}", msg);
            return Err(msg.into());
        };
        let sport: u32 = *matches.get_one::<u16>("sport").unwrap() as u32;
        let dport = *matches.get_one::<u16>("dport").unwrap() as u32;

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
        // Get protocol to use (preserving user-specified order for --any fallback)
        let p_types: Vec<ProtocolType> = {
            let mut seen = HashSet::new();
            matches
                .get_many::<String>("p_type")
                .unwrap_or_default()
                .filter_map(|s| ProtocolType::from_str(s))
                .filter(|p| seen.insert(*p))
                .collect()
        };

        let num_p_types = p_types.len();

        // Create the Configuration for each Worker
        let configs: Vec<Configuration> = sender_ids
            .iter()
            .flat_map(|&worker_id| {
                p_types.iter().enumerate().map(move |(idx, &p_type)| {
                    let origin_id = if num_p_types == 1 {
                        // Single p_type -> single Origin
                        SINGLE_ORIGIN
                    } else {
                        // Multiple p_type -> iterate Origin IDs
                        (idx + 1) as u32
                    };

                    Configuration {
                        worker_id,
                        origin: Some(Origin {
                            src: Some(src),
                            sport,
                            dport,
                            origin_id,
                            p_type: p_type as i32,
                        }),
                    }
                })
            })
            .collect();

        configs
    };

    // Get the target IP addresses (either --hitlist or --target)
    let is_shuffle = matches.get_flag("shuffle");
    let (hitlist_path, (targets, is_ipv6)) =
        if let Some(target_str) = matches.get_one::<String>("target") {
            (
                target_str.as_str(),
                get_targets(target_str, &configurations, is_shuffle),
            )
        } else {
            let path = matches.get_one::<String>("hitlist").unwrap().as_str();
            (path, get_hitlist(path, &configurations, is_shuffle))
        };
    let dns_record = matches.get_one::<String>("query");
    let is_cli = matches.get_flag("stream");
    let is_parquet = matches.get_flag("parquet");
    let worker_interval = *matches.get_one::<u32>("worker_interval").unwrap();
    let probe_interval = *matches.get_one::<u32>("probe_interval").unwrap();
    let probing_rate = *matches.get_one::<u32>("rate").unwrap();
    let number_of_probes = *matches.get_one::<u32>("nprobes").unwrap();
    let hitlist_length = targets.len();

    // Get protocol and IP version
    let ip_version = if is_ipv6 { "(IPv6)" } else { "(IPv4)" };

    info!("[CLI] Performing {m_type} {ip_version} measurement using targeting {} addresses, with a rate of {}, and a worker-interval of {worker_interval} seconds",
             hitlist_length.with_separator(),
             probing_rate.with_separator(),
    );

    // Print the origins used
    info!("[CLI] Workers send probes using the following configurations:");
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_titles(
        row![b->"Hostname", b->"Worker ID", b->"src IP", b->"src Port", b->"Dst Port", b->"Protocol"],
    );

    for config in &configurations {
        if let Some(origin) = &config.origin {
            let (worker_name, worker_id_str) = if config.worker_id == ALL_WORKERS {
                (
                    format!("All {}", worker_map.len()),
                    "ALL".to_string(),
                )
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
                origin.dport,
                origin.p_type()
            ]);
        }
    }
    table.printstd();

    // get optional path to write results to
    let path = matches.get_one::<String>("out").unwrap().to_string();
    validate_path_perms(&path)?;

    let trace_options = if m_type == MeasurementType::AnycastTraceroute {
        Some(TraceOptions {
            max_failures: *matches.get_one::<u32>("trace_max_failures").unwrap(),
            max_hops: *matches.get_one::<u32>("trace_max_hop").unwrap(),
            timeout: *matches.get_one::<u32>("trace_timeout").unwrap(),
            initial_hop: *matches.get_one::<u32>("trace_initial_hop").unwrap(),
            star_unresponsive: *matches.get_one::<bool>("trace_star").unwrap(),
        })
    } else {
        None
    };

    if is_any_protocol {
        let unique_origins: HashSet<_> = configurations
            .iter()
            .filter_map(|c| c.origin.as_ref().map(|o| o.origin_id))
            .collect();
        if unique_origins.len() < 2 {
            let msg = "[CLI] --any requires at least two protocols (e.g., -p icmp,tcp)";
            error!("{}", msg);
            return Err(msg.into());
        }
    }

    // Create the measurement definition and send it to the orchestrator
    let m_definition = ScheduleMeasurement {
        probing_rate,
        configurations,
        m_type: m_type.into(),
        worker_interval,
        is_responsive,
        hitlist: targets,
        record: dns_record.cloned(),
        url: url.cloned(),
        probe_interval,
        number_of_probes,
        is_ipv6,
        is_record,
        trace_options,
        is_any_protocol,
    };

    let args = MeasurementExecutionArgs {
        is_cli,
        is_parquet,
        is_shuffle,
        hitlist_path,
        hitlist_length,
        out_path: path,
        worker_map,
        is_record,
    };

    grpc_client
        .do_measurement_to_server(m_definition, args, m_type)
        .await
}

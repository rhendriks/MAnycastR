mod writer;

use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bimap::BiHashMap;
use chrono::Local;
use clap::ArgMatches;
use flate2::read::GzDecoder;
use indicatif::{ProgressBar, ProgressStyle};
use prettytable::{color, format, row, Attr, Cell, Row, Table};
use rand::seq::SliceRandom;
use tokio::sync::mpsc::unbounded_channel;
use tonic::codec::CompressionEncoding;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use tonic::Request;

use custom_module::manycastr::{
    controller_client::ControllerClient, Address, Configuration, Empty, Origin,
    ScheduleMeasurement, Targets, TaskResult,
};
use custom_module::Separated;

use crate::cli::writer::{get_csv_metadata, write_results_parquet};
use crate::cli::writer::write_results;
use crate::cli::writer::{MetadataArgs, WriteConfig};
use crate::{custom_module, ALL_ID, A_ID, CHAOS_ID, ICMP_ID, TCP_ID};

/// A CLI client that creates a connection with the 'orchestrator' and sends the desired commands based on the command-line input.
pub struct CliClient {
    grpc_client: ControllerClient<Channel>,
}

/// Execute the command-line arguments and send the desired commands to the orchestrator.
///
/// # Arguments
///
/// * 'args' - the user-defined command-line arguments
#[tokio::main]
pub async fn execute(args: &ArgMatches) -> Result<(), Box<dyn Error>> {
    let server_address = args.get_one::<String>("orchestrator").unwrap();
    let fqdn = args.get_one::<String>("tls");

    // Connect with orchestrator
    println!("[CLI] Connecting to orchestrator - {}", server_address);
    let mut grpc_client = CliClient::connect(server_address, fqdn)
        .await
        .expect("Unable to connect to orchestrator")
        .send_compressed(CompressionEncoding::Zstd);

    // Obtain connected worker information
    let response = grpc_client
        .list_workers(Request::new(Empty::default()))
        .await
        .expect("Connection to orchestrator failed");

    let mut cli_client = CliClient { grpc_client };

    if args.subcommand_matches("worker-list").is_some() {
        // Perform the worker-list command
        println!("[CLI] Requesting workers list from orchestrator");
        // Pretty print to command-line
        let mut table = Table::new();
        table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
        table.add_row(Row::new(vec![
            Cell::new("Hostname")
                .with_style(Attr::Bold)
                .with_style(Attr::ForegroundColor(color::GREEN)),
            Cell::new("Worker ID")
                .with_style(Attr::Bold)
                .with_style(Attr::ForegroundColor(color::GREEN)),
            Cell::new("Status")
                .with_style(Attr::Bold)
                .with_style(Attr::ForegroundColor(color::GREEN)),
            Cell::new("Unicast IPv4")
                .with_style(Attr::Bold)
                .with_style(Attr::ForegroundColor(color::GREEN)),
            Cell::new("Unicast IPv6")
                .with_style(Attr::Bold)
                .with_style(Attr::ForegroundColor(color::GREEN)),
        ]));

        let mut connected_workers = 0;
        let mut workers = response.into_inner().workers;
        workers.sort_by(|a, b| a.worker_id.cmp(&b.worker_id));

        for worker in workers {
            let unicast_v4 = if let Some(addr) = &worker.unicast_v4 {
                addr.to_string()
            } else {
                "N/A".to_string()
            };

            let unicast_v6 = if let Some(addr) = &worker.unicast_v6 {
                addr.to_string()
            } else {
                "N/A".to_string()
            };

            table.add_row(row![
                worker.hostname,
                worker.worker_id,
                worker.status,
                unicast_v4,
                unicast_v6
            ]);
            if worker.status != "DISCONNECTED" {
                connected_workers += 1;
            }
        }

        table.printstd();
        println!("[CLI] Total connected workers: {}", connected_workers);

        Ok(())
    } else if let Some(matches) = args.subcommand_matches("start") {
        // Start a MAnycastR measurement
        let is_unicast = matches.get_flag("unicast");
        let is_divide = matches.get_flag("divide");
        let is_responsive = matches.get_flag("responsive");
        let mut is_latency = matches.get_flag("latency");

        if is_responsive && is_divide {
            panic!("Incompatible flags: Responsive mode cannot be combined with divide-and-conquer measurements.");
        } else if is_latency && (is_divide || is_responsive) {
            panic!("Incompatible flags: Latency mode cannot be combined with divide-and-conquer or responsive measurements.");
        } else if is_unicast && is_latency {
            is_latency = false; // Unicast mode is latency by design
        }

        // Map to convert hostnames to worker IDs and vice versa
        let worker_map: BiHashMap<u32, String> = response
            .into_inner()
            .workers
            .into_iter()
            .map(|worker| (worker.worker_id, worker.hostname)) // .clone() is no longer needed on hostname
            .collect();

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

        // Temporarily broken
        if is_responsive && is_unicast && m_type == TCP_ID {
            panic!("Responsive mode not supported for unicast TCP measurements");
        }

        let is_config = matches.contains_id("configuration");

        // Get the workers that have to send out probes
        let sender_ids: Vec<u32> = matches.get_one::<String>("selective").map_or_else(
            || {
                println!(
                    "[CLI] Probes will be sent out from all ({}) workers",
                    worker_map.len()
                );
                Vec::new()
            },
            |worker_entries_str| {
                println!("[CLI] Selective probing using specified workers...");
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
                                panic!("Worker ID '{}' is not a known worker.", entry_str);
                            }
                        } else if let Some(&found_id) = worker_map.get_by_right(entry_str) {
                            // Try to find the hostname in the map
                            Some(found_id)
                        } else {
                            panic!(
                                "'{}' is not a valid worker ID or known hostname.",
                                entry_str
                            );
                        }
                    })
                    .collect()
            },
        );

        // Print selected workers
        if !sender_ids.is_empty() {
            println!("[CLI] Selective probing using the following workers:");
            sender_ids.iter().for_each(|id| {
                let hostname = worker_map.get_by_left(id).unwrap_or_else(|| {
                    panic!("Worker ID {} is not a connected worker!", id);
                });
                println!("[CLI]\t * ID: {}, Hostname: {}", id, hostname);
            });
        }

        // Read the configuration file (unnecessary for unicast)
        let configurations = if is_config {
            let conf_file = matches.get_one::<String>("configuration").unwrap();
            println!("[CLI] Using configuration file: {}", conf_file);
            let file = File::open(conf_file)
                .unwrap_or_else(|_| panic!("Unable to open configuration file {}", conf_file));
            let buf_reader = BufReader::new(file);
            let mut origin_id = 0;
            let mut is_ipv6: Option<bool> = None;
            let configurations: Vec<Configuration> = buf_reader // Create a vector of addresses from the file
                .lines()
                .filter_map(|line| {
                    let line = line.expect("Unable to read configuration line");
                    let line = line.trim();
                    if line.is_empty() || line.starts_with("#") {
                        return None;
                    } // Skip comments and empty lines

                    let parts: Vec<&str> = line.splitn(2, " - ").map(|s| s.trim()).collect();
                    if parts.len() != 2 {
                        panic!("Invalid configuration format: {}", line);
                    }

                    // Parse the worker ID
                    let worker_id = if parts[0] == "ALL" {
                        u32::MAX
                    } else if let Ok(id_val) = parts[0].parse::<u32>() {
                        if !worker_map.contains_left(&id_val) {
                            panic!("Worker ID {} is not a known worker.", id_val);
                        }
                        id_val
                    } else if let Some(&found_id) = worker_map.get_by_right(parts[0]) {
                        // Try to find the hostname in the map
                        found_id
                    } else {
                        panic!("'{}' is not a valid worker ID or known hostname.", parts[0]);
                    };

                    let addr_ports: Vec<&str> = parts[1].split(',').map(|s| s.trim()).collect();
                    if addr_ports.len() != 3 {
                        panic!("Invalid configuration format: {}", line);
                    }
                    let src = Address::from(addr_ports[0]);

                    if let Some(v6) = is_ipv6 {
                        if v6 != src.is_v6() {
                            panic!("Configuration file contains mixed IPv4 and IPv6 addresses!");
                        }
                    } else {
                        is_ipv6 = Some(src.is_v6());
                    }

                    // Parse to u16 first, must fit in header
                    let sport =
                        u16::from_str(addr_ports[1]).expect("Unable to parse source port") as u32;
                    let dport = u16::from_str(addr_ports[2])
                        .expect("Unable to parse destination port")
                        as u32;
                    origin_id += 1;

                    Some(Configuration {
                        worker_id,
                        origin: Some(Origin {
                            src: Some(src),
                            sport,
                            dport,
                            origin_id,
                        }),
                    })
                })
                .collect();
            if configurations.is_empty() {
                panic!("No valid configurations found in file {}", conf_file);
            }

            configurations
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

        // TODO implement feed of addresses instead of a hitlist file
        // format: address,tx -> tx optional to specify from which site to probe
        // protocol and ports used are pre-configured when starting a live measurement at the CLI

        // Get the target IP addresses
        let hitlist_path = matches.get_one::<String>("IP_FILE").unwrap();
        let is_shuffle = matches.get_flag("shuffle");

        let (ips, is_ipv6) = get_hitlist(hitlist_path, &configurations, is_unicast, is_shuffle);

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
        let hitlist_length = ips.len();

        println!("[CLI] Performing {} measurement targeting {} addresses, with a rate of {}, and an interval of {}",
                 t_type,
                 hitlist_length.with_separator(),
                 probing_rate.with_separator(),
                 worker_interval
        );

        if is_responsive {
            println!("[CLI] Responsive mode enabled");
        }

        if is_latency {
            println!("[CLI] Latency mode enabled");
        }

        // Print the origins used
        if is_unicast {
            let unicast_origin = configurations.first().unwrap().origin.unwrap();
            println!(
                "[CLI] Unicast probing with src port {} and dst port {}",
                unicast_origin.sport, unicast_origin.dport
            );
        } else if is_config {
            println!("[CLI] Workers send probes using the following configurations:");
            for configuration in configurations.iter() {
                if let Some(origin) = &configuration.origin {
                    if configuration.worker_id == u32::MAX {
                        println!(
                            "\t* All workers, source IP: {}, source port: {}, destination port: {}",
                            origin.src.unwrap(),
                            origin.sport,
                            origin.dport
                        );
                    } else {
                        let worker_hostname = worker_map
                            .get_by_left(&configuration.worker_id)
                            .expect("Worker ID not found");
                        println!(
                            "\t* worker {} (with ID: {:<2}), source IP: {}, source port: {}, destination port: {}",
                            worker_hostname, configuration.worker_id, origin.src.unwrap(), origin.sport, origin.dport
                        );
                    }
                }
            }
        } else {
            let anycast_origin = configurations.first().unwrap().origin.unwrap();

            println!(
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
            targets: Some(Targets {
                dst_list: ips,
                is_discovery: None,
            }),
            record: dns_record.to_string(),
            url,
            probe_interval,
            number_of_probes,
        };

        let args = MeasurementExecutionArgs {
            is_cli,
            is_shuffle,
            hitlist_path,
            hitlist_length,
            out_path: path,
            is_config,
            worker_map,
        };

        cli_client
            .do_measurement_to_server(m_definition, args)
            .await
    } else {
        panic!("Unrecognized command");
    }
}

fn validate_path_perms(path: Option<&String>) -> Option<Result<(), Box<dyn Error>>> {
    if let Some(path_str) = path {
        let path = Path::new(path_str);

        if !path_str.ends_with('/') {
            // User provided a file
            if path.exists() {
                if path.is_dir() {
                    println!("[CLI] Path is already a directory, exiting");
                    return Some(Err("Path is already a directory".into()));
                } else if fs::metadata(path)
                    .expect("Unable to get path metadata")
                    .permissions()
                    .readonly()
                {
                    println!("[CLI] Lacking write permissions for file {}", path_str);
                    return Some(Err("Lacking write permissions".into()));
                } else {
                    println!(
                        "[CLI] Overwriting existing file {} when measurement is done",
                        path_str
                    );
                }
            } else {
                println!("[CLI] Writing results to new file {}", path_str);

                // File does not yet exist, create it to verify permissions
                File::create(path)
                    .expect("Unable to create output file")
                    .sync_all()
                    .expect("Unable to sync file");
                fs::remove_file(path).expect("Unable to remove file");
            }
        } else {
            // User provided a directory
            if path.exists() {
                if !path.is_dir() {
                    println!("[CLI] Path is already a file, exiting");
                    return Some(Err("Cannot make dir, file with name already exists.".into()));
                } else if fs::metadata(path)
                    .expect("Unable to get path metadata")
                    .permissions()
                    .readonly()
                {
                    println!("[CLI] Lacking write permissions for directory {}", path_str);
                    return Some(Err("Path is not writable".into()));
                } else {
                    println!("[CLI] Writing results to existing directory {}", path_str);
                }
            } else {
                println!("[CLI] Writing results to new directory {}", path_str);

                // Attempt creating path to verify permissions
                fs::create_dir_all(path).expect("Unable to create output directory");
            }
        }
    }
    None
}

/// Get the hitlist from a file.
///
/// # Arguments
///
/// * 'hitlist_path' - path to the hitlist file
///
/// * 'configurations' - list of configurations to check the source address type
///
/// * 'is_unicast' - boolean whether the measurement is unicast or anycast
///
/// * 'is_shuffle' - boolean whether the hitlist should be shuffled or not
///
/// # Returns
///
/// * A tuple containing a vector of addresses and a boolean indicating whether the addresses are IPv6 or IPv4.
///
/// # Panics
///
/// * If the hitlist file cannot be opened.
///
/// * If the anycast source address type (v4 or v6) does not match the hitlist addresses.
///
/// * If the hitlist addresses are of mixed types (v4 and v6).
fn get_hitlist(
    hitlist_path: &String,
    configurations: &[Configuration],
    is_unicast: bool,
    is_shuffle: bool,
) -> (Vec<Address>, bool) {
    let file =
        File::open(hitlist_path).unwrap_or_else(|_| panic!("Unable to open file {}", hitlist_path));

    // Create reader based on file extension
    let reader: Box<dyn BufRead> = if hitlist_path.ends_with(".gz") {
        let decoder = GzDecoder::new(file);
        Box::new(BufReader::new(decoder))
    } else {
        Box::new(BufReader::new(file))
    };

    let mut ips: Vec<Address> = reader // Create a vector of addresses from the file
        .lines()
        .map_while(Result::ok) // Handle potential errors
        .filter(|l| !l.trim().is_empty()) // Skip empty lines
        .map(Address::from)
        .collect();
    let is_ipv6 = ips.first().unwrap().is_v6();

    // Panic if the source IP is not the same type as the addresses
    if !is_unicast
        && configurations
            .first()
            .expect("Empty configuration list")
            .origin
            .expect("No origin found")
            .src
            .expect("No source address")
            .is_v6()
            != is_ipv6
    {
        panic!(
            "Hitlist addresses are not the same type as the source addresses used! (IPv4 & IPv6)"
        );
    }
    // Panic if the ips in the hitlist are not all the same type
    if ips.iter().any(|ip| ip.is_v6() != is_ipv6) {
        panic!("Hitlist addresses are not all of the same type! (mixed IPv4 & IPv6)");
    }

    // Shuffle the hitlist, if desired
    if is_shuffle {
        ips.as_mut_slice().shuffle(&mut rand::rng());
    }
    (ips, is_ipv6)
}

pub struct MeasurementExecutionArgs<'a> {
    /// Determines whether results should be streamed to the command-line interface as they arrive.
    pub is_cli: bool,

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
}

impl CliClient {
    /// Perform a measurement at the orchestrator, await measurement results, and write them to a file.
    ///
    /// # Arguments
    ///
    /// * 'm_definition' - measurement definition created from the command-line arguments
    ///
    /// * 'is_cli' - boolean whether the results should be streamed to the CLI or not
    ///
    /// * 'is_shuffle' - boolean whether the hitlist should be shuffled or not
    ///
    /// * 'hitlist' - hitlist file path
    ///
    /// * 'hitlist_length' - length of hitlist (i.e., number of target addresses)
    ///
    /// * 'path' - optional path for output file (default is current directory)
    ///
    /// * 'is_config' - boolean whether the measurement is configuration-based or not
    ///
    /// * 'worker_map' - bidirectional map of worker IDs to hostnames
    async fn do_measurement_to_server(
        &mut self,
        m_definition: ScheduleMeasurement,
        args: MeasurementExecutionArgs<'_>,
    ) -> Result<(), Box<dyn Error>> {
        let is_divide = m_definition.is_divide;
        let is_ipv6 = m_definition.is_ipv6;
        let probing_rate = m_definition.probing_rate as f32;
        let worker_interval = m_definition.worker_interval;
        let m_type = m_definition.m_type;
        let is_unicast = m_definition.is_unicast;
        let is_latency = m_definition.is_latency;
        let is_responsive = m_definition.is_responsive;
        let origin_str = if is_unicast {
            m_definition
                .configurations
                .first()
                .and_then(|conf| conf.origin.as_ref())
                .map(|origin| {
                    format!(
                        "Unicast (source port: {}, destination port: {})",
                        origin.sport, origin.dport
                    )
                })
                .expect("No unicast origin found")
        } else if args.is_config {
            "Anycast configuration-based".to_string()
        } else {
            m_definition
                .configurations
                .first()
                .and_then(|conf| conf.origin.as_ref())
                .map(|origin| {
                    format!(
                        "Anycast (source IP: {}, source port: {}, destination port: {})",
                        origin.src.unwrap(),
                        origin.sport,
                        origin.dport
                    )
                })
                .expect("No anycast origin found")
        };

        // List of Worker IDs that are sending out probes (empty means all)
        let probing_workers: Vec<String> = if m_definition
            .configurations
            .iter()
            .any(|config| config.worker_id == u32::MAX)
        {
            Vec::new() // all workers are probing
        } else {
            // Get list of unique worker hostnames that are probing
            m_definition
                .configurations
                .iter()
                .map(|config| {
                    args.worker_map
                        .get_by_left(&config.worker_id)
                        .unwrap_or_else(|| {
                            panic!(
                                "Worker ID {} is not a connected worker!",
                                config.worker_id
                            )
                        })
                        .clone()
                })
                .collect::<HashSet<String>>() // Use HashSet to ensure uniqueness
                .into_iter()
                .collect::<Vec<String>>()
        };

        let number_of_probers = if probing_workers.is_empty() {
            args.worker_map.len() as f32
        } else {
            probing_workers.len() as f32
        };

        let m_time = if is_divide || is_latency {
            ((args.hitlist_length as f32 / (probing_rate * number_of_probers)) + 1.0) / 60.0
        } else {
            (((number_of_probers - 1.0) * worker_interval as f32) // Last worker starts probing
                + (args.hitlist_length as f32 / probing_rate) // Time to probe all addresses
                + 1.0) // Time to wait for last replies
                / 60.0 // Convert to minutes
        };

        if is_divide {
            println!("[CLI] Divide-and-conquer enabled");
        }
        println!(
            "[CLI] This measurement will take an estimated {:.2} minutes",
            m_time
        );

        let response = self
            .grpc_client
            .do_measurement(Request::new(m_definition.clone()))
            .await;
        if let Err(e) = response {
            println!(
                "[CLI] Orchestrator did not perform the measurement for reason: '{}'",
                e.message()
            );
            return Err(Box::new(e));
        }
        let start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let timestamp_start = Local::now();
        let timestamp_start_str = timestamp_start.format("%Y-%m-%dT%H_%M_%S").to_string();
        println!(
            "[CLI] Measurement started at {}",
            timestamp_start.format("%H:%M:%S")
        );

        // Progress bar
        let total_steps = (m_time * 60.0) as u64; // measurement_length in seconds
        let pb = ProgressBar::new(total_steps);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("#>-"),
        );
        let is_done = Arc::new(AtomicBool::new(false));
        let is_done_clone = is_done.clone();

        // Spawn a separate async task to update the progress bar
        tokio::spawn(async move {
            // If we are streaming to the CLI, we cannot use a progress bar
            if !args.is_cli {
                for _ in 0..total_steps {
                    if is_done_clone.load(Ordering::Relaxed) {
                        break;
                    }
                    pb.inc(1); // Increment the progress bar by one step
                    tokio::time::sleep(Duration::from_secs(1)).await; // Simulate time taken for each step
                }
            }
        });

        let mut graceful = false; // Will be set to true if the stream closes gracefully
                                  // Obtain the Stream from the orchestrator and read from it
        let mut stream = response
            .expect("Unable to obtain the orchestrator stream")
            .into_inner();
        // Channel for writing results to file
        let (tx_r, rx_r) = unbounded_channel();

        // Get measurement type
        let type_str = match m_type as u8 {
            ICMP_ID => "ICMP",
            A_ID => "DNS",
            TCP_ID => "TCP",
            CHAOS_ID => "CHAOS",
            _ => "ICMP",
        };
        let type_str = if is_ipv6 {
            format!("{}v6", type_str)
        } else {
            format!("{}v4", type_str)
        };

        // Determine the type of measurement
        let filetype = if is_unicast { "GCD_" } else { "MAnycast_" };

        // Output file
        let file_path = if let Some(path) = args.out_path {
            if path.ends_with('/') {
                // user provided a path, use default naming convention for file
                format!(
                    "{}{}{}{}.csv.gz",
                    path, filetype, type_str, timestamp_start_str
                )
            } else {
                // user provided a file (with possibly a path)
                path.to_string()
            }
        } else {
            // write file to current directory using default naming convention
            format!("./{}{}{}.csv.gz", filetype, type_str, timestamp_start_str)
        };

        // Create the output file
        let file = File::create(file_path).expect("Unable to create file");

        let metadata_args = MetadataArgs {
            is_divide,
            origin_str,
            hitlist: args.hitlist_path,
            is_shuffle: args.is_shuffle,
            m_type_str: type_str,
            probing_rate: probing_rate as u32,
            interval: worker_interval,
            active_workers: probing_workers,
            all_workers: &args.worker_map,
            configurations: &m_definition.configurations,
            is_config: args.is_config,
            is_latency,
            is_responsive,
        };

        let is_multi_origin = if is_unicast {
            false
        } else {
            // Check if any configuration has origin_id that is not 0 or u32::MAX
            m_definition.configurations.iter().any(|conf| {
                conf.origin
                    .as_ref()
                    .is_some_and(|origin| origin.origin_id != 0 && origin.origin_id != u32::MAX)
            })
        };

        let config = WriteConfig {
            print_to_cli: args.is_cli,
            output_file: file,
            metadata_args,
            m_type,
            is_multi_origin,
            is_symmetric: is_unicast || is_latency,
            worker_map: args.worker_map.clone(),
        };

        // Start thread that writes results to file
        write_results_parquet(rx_r, config);
        // write_results(rx_r, config);

        let mut replies_count = 0;
        'mloop: while let Some(task_result) = match stream.message().await {
            Ok(Some(result)) => Some(result),
            Ok(None) => {
                eprintln!("Stream closed by orchestrator");
                break 'mloop;
            } // Stream is exhausted
            Err(e) => {
                eprintln!("Error receiving message: {}", e);
                break 'mloop;
            }
        } {
            // A default result notifies the CLI that it should not expect any more results
            if task_result == TaskResult::default() {
                tx_r.send(task_result).unwrap(); // Let the results channel know that we are done
                graceful = true;
                break;
            }

            replies_count += task_result.result_list.len();
            // Send the results to the file channel
            tx_r.send(task_result).unwrap();
        }

        is_done.store(true, Ordering::Relaxed); // Signal the progress bar to stop

        let end = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let length = (end - start) as f64 / 1_000_000_000.0; // Measurement length in seconds
        println!("[CLI] Waited {:.6} seconds for results.", length);
        println!(
            "[CLI] Time of end measurement {}",
            Local::now().format("%H:%M:%S")
        );
        println!(
            "[CLI] Number of replies captured: {}",
            replies_count.with_separator()
        );

        // If the stream closed during a measurement
        if !graceful {
            tx_r.send(TaskResult::default()).unwrap(); // Let the results channel know that we are done
            println!("[CLI] Measurement ended prematurely!");
        }

        tx_r.closed().await; // Wait for all results to be written to file

        Ok(())
    }

    /// Connect to the orchestrator
    ///
    /// # Arguments
    ///
    /// * 'address' - the address of the orchestrator (e.g., 10.10.10.10:50051)
    ///
    /// * 'fqdn' - an optional string that contains the FQDN of the orchestrator certificate (if TLS is enabled)
    ///
    /// # Returns
    ///
    /// A gRPC client that is connected to the orchestrator
    ///
    /// # Panics
    ///
    /// If the connection to the orchestrator fails
    ///
    /// # Remarks
    ///
    /// TLS enabled requires a certificate at ./tls/orchestrator.crt
    async fn connect(
        address: &str,
        fqdn: Option<&String>,
    ) -> Result<ControllerClient<Channel>, Box<dyn Error>> {
        let channel = if let Some(fqdn) = fqdn {
            // Secure connection
            let addr = format!("https://{}", address);

            // Load the CA certificate used to authenticate the orchestrator
            let pem = fs::read_to_string("tls/orchestrator.crt")
                .expect("Unable to read CA certificate at ./tls/orchestrator.crt");
            let ca = Certificate::from_pem(pem);

            let tls = ClientTlsConfig::new().ca_certificate(ca).domain_name(fqdn);

            let builder = Channel::from_shared(addr.to_owned())?; // Use the address provided
            builder
                .tls_config(tls)
                .expect("Unable to set TLS configuration")
                .connect()
                .await
                .expect("Unable to connect to orchestrator")
        } else {
            // Unsecure connection
            let addr = format!("http://{}", address);

            Channel::from_shared(addr.to_owned())
                .expect("Unable to set address")
                .connect()
                .await
                .expect("Unable to connect to orchestrator")
        };
        // Create client with secret token that is used to authenticate client commands.
        let client = ControllerClient::new(channel);

        Ok(client)
    }
}

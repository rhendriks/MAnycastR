use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fs, io};

use chrono::Local;
use clap::ArgMatches;
use csv::Writer;
use flate2::read::GzDecoder;
use indicatif::{ProgressBar, ProgressStyle};
use prettytable::{color, format, Attr, Cell, Row, Table};
use rand::seq::SliceRandom;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tonic::codec::CompressionEncoding;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use tonic::Request;

use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::BufWriter;

use custom_module::manycastr::{
    controller_client::ControllerClient, reply::Value::Ping as ResultPing, udp_result::Value::DnsARecord,
    reply::Value::Tcp as ResultTcp, reply::Value::Udp as ResultUdp, udp_result::Value::DnsChaos,
    Address, Configuration, Empty, Origin, Reply,
    ScheduleMeasurement, Targets, TaskResult,
};
use custom_module::Separated;

use crate::custom_module;

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
        ]));

        for worker in response.into_inner().workers {
            let measurements_str = if worker.measurements.is_empty() {
                "Idle".to_string()
            } else {
                format!(
                    "Active: {}",
                    worker
                        .measurements
                        .iter()
                        .map(|m| m.to_string())
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            };

            table.add_row(prettytable::row!(
                worker.metadata.unwrap().hostname,
                worker.worker_id,
                measurements_str,
            ));
        }
        table.printstd();
        println!("[CLI] Total workers: {}", table.len() - 1);

        Ok(())
    } else if let Some(matches) = args.subcommand_matches("start") {
        // Start a MAnycastR measurement
        let is_unicast = matches.get_flag("unicast");
        let is_divide = matches.get_flag("divide");
        let is_responsive = matches.get_flag("responsive");
        if is_responsive && is_divide {
            panic!("Responsive mode not supported for divide-and-conquer measurements");
        }

        // Map worker IDs to hostnames
        let worker_map: HashMap<u32, String> = response
            .into_inner()
            .workers
            .into_iter()
            .filter_map(|worker| {
                worker
                    .metadata
                    .map(|metadata| (worker.worker_id, metadata.hostname))
            })
            .collect();

        // Get optional opt-out URL
        let url = matches.get_one::<String>("url").unwrap().clone();

        // Source IP for the measurement
        let src = matches
            .get_one::<String>("address")
            .map(|addr| Address::from(addr));

        // Get the measurement type
        let measurement_type: u8 = match matches
            .get_one::<String>("type")
            .unwrap()
            .to_lowercase()
            .as_str()
        {
            "icmp" => 1,
            "dns" => 2,
            "tcp" => 3,
            "chaos" => 4,
            "all" => 255,
            _ => panic!("Invalid measurement type! (can be either ICMP, DNS, TCP, all, or CHAOS)"),
        };

        let is_config = matches.contains_id("configuration");

        // Get the workers that have to send out probes
        let sender_ids = matches.get_one::<String>("selective").map_or_else(
            || {
                println!("[CLI] Probes will be sent out from all workers");
                Vec::new()
            },
            |worker_entries| {
                worker_entries
                    .trim_matches(['[', ']'])
                    .split(',')
                    .filter_map(|id| {
                        id.trim().parse::<u32>()
                            .map_err(|e| {
                                eprintln!("Unable to parse worker ID '{}': {}", id, e);
                            })
                            .ok()
                    })
                    .collect()
            },
        );

        // Print selected workers
        if !sender_ids.is_empty() {
            println!("[CLI] Selective probing using the following workers:");
            sender_ids.iter().for_each(|id| {
                let hostname = worker_map.get(id).unwrap_or_else(|| {
                    panic!("Worker ID {} is not a connected worker!", id);
                });
                println!("[CLI]\t * ID: {}, Hostname: {}", id, hostname);
            });
        }

        // Read the configuration file (unnecessary for unicast)
        let configurations = if is_config && !is_unicast {
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
                        if !worker_map.contains_key(&id_val) {
                            panic!("Worker ID {} is not a known worker.", id_val);
                        }
                        id_val
                    } else {
                        // Assume hostname
                        worker_map
                            .iter()
                            .find_map(|(id_key, hostname_val)| {
                                if hostname_val == parts[0] {
                                    Some(*id_key)
                                } else {
                                    None
                                }
                            })
                            .unwrap_or_else(|| {
                                panic!(
                                    "Unable to parse '{}' as 'ALL', a worker ID, or a connected worker hostname.",
                                    parts[0]
                                );
                            })
                    };

                    let addr_ports: Vec<&str> = parts[1].split(',').map(|s| s.trim()).collect();
                    if addr_ports.len() != 3 {
                        panic!("Invalid configuration format: {}", line);
                    }
                    let src = Address::from(addr_ports[0]);
                    if is_ipv6.is_none() {
                        is_ipv6 = Some(src.is_v6());
                    } else if is_ipv6.unwrap() != src.is_v6() {
                        panic!("Configuration file contains mixed IPv4 and IPv6 addresses!");
                    }
                    
                    // Parse to u16 first, must fit in header
                    let sport = u16::from_str(addr_ports[1]).expect("Unable to parse source port") as u32;
                    let dport = u16::from_str(addr_ports[2]).expect("Unable to parse destination port") as u32;
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
                    if measurement_type == 2 || measurement_type == 4 {
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
                        origin_id: 0, // Only one anycast origin
                    }),
                }]
            } else if is_unicast {
                // No configurations for unicast measurements
                vec![]
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
                            origin_id: 0, // Only one anycast origin
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
        let hitlist_path = matches
            .get_one::<String>("IP_FILE")
            .expect("No hitlist file provided!");
        let file = File::open(hitlist_path)
            .unwrap_or_else(|_| panic!("Unable to open file {}", hitlist_path));

        // Create reader based on file extension
        let reader: Box<dyn BufRead> = if hitlist_path.ends_with(".gz") {
            let decoder = GzDecoder::new(file);
            Box::new(BufReader::new(decoder))
        } else {
            Box::new(BufReader::new(file))
        };

        let mut ips: Vec<Address> = reader // Create a vector of addresses from the file
            .lines()
            .filter_map(|l| l.ok()) // Handle potential errors
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
            panic!("Hitlist addresses are not the same type as the source addresses used! (IPv4 & IPv6)");
        }
        // Panic if the ips in the hitlist are not all the same type
        if ips.iter().any(|ip| ip.is_v6() != is_ipv6) {
            panic!("Hitlist addresses are not all of the same type! (mixed IPv4 & IPv6)");
        }

        // Shuffle the hitlist, if desired
        let is_shuffle = matches.get_flag("shuffle");
        if is_shuffle {
            let mut rng = rand::rng();
            ips.as_mut_slice().shuffle(&mut rng);
        }

        // CHAOS value to send in the DNS query
        let dns_record = if measurement_type == 4 || measurement_type == 255 {
            // get CHAOS query
            matches
                .get_one::<String>("query")
                .map_or("hostname.bind", |q| q.as_str())
        } else if measurement_type == 2 {
            // TODO change default A record value
            matches
                .get_one::<String>("query")
                .map_or("any.dnsjedi.org", |q| q.as_str())
        } else {
            ""
        };

        // Check for command-line option that determines whether to stream to CLI
        let is_cli = matches.get_flag("stream");

        // Get interval, rate. Default values are 1 and 1000 respectively
        let interval = *matches.get_one::<u32>("interval").unwrap();
        let rate = *matches.get_one::<u32>("rate").unwrap();
        let t_type = match measurement_type {
            1 => "ICMP/ping",
            2 => "UDP/DNS",
            3 => "TCP/SYN-ACK",
            4 => "UDP/CHAOS",
            255 => "All (ICMP,UDP,TCP)",
            _ => "ICMP/ping",
        };
        let hitlist_length = ips.len();

        println!("[CLI] Performing {} measurement targeting {} addresses, with a rate of {}, and an interval of {}",
                 t_type,
                 hitlist_length.with_separator(),
                 rate.with_separator(),
                 interval
        );

        if is_responsive {
            println!("[CLI] Responsive mode enabled");
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
                            origin.src.unwrap(), origin.sport, origin.dport
                        );
                    } else {
                        let worker_hostname = worker_map
                            .get(&configuration.worker_id)
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
                anycast_origin.src.unwrap(), anycast_origin.sport, anycast_origin.dport
            );
        }

        // get optional path to write results to
        let path = matches.get_one::<String>("out");
        if let Some(path_str) = path {
            let path = Path::new(path_str);

            if !path_str.ends_with('/') {
                // User provided a file
                if path.exists() {
                    if path.is_dir() {
                        println!("[CLI] Path is already a directory, exiting");
                        return Err("Path is already a directory".into());
                    } else if fs::metadata(path)
                        .expect("Unable to get path metadata")
                        .permissions()
                        .readonly()
                    {
                        println!("[CLI] Lacking write permissions for file {}", path_str);
                        return Err("Lacking write permissions".into());
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
                        return Err("Cannot make dir, file with name already exists.".into());
                    } else if fs::metadata(path)
                        .expect("Unable to get path metadata")
                        .permissions()
                        .readonly()
                    {
                        println!("[CLI] Lacking write permissions for directory {}", path_str);
                        return Err("Path is not writable".into());
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

        // Create the measurement definition and send it to the orchestrator
        let measurement_definition = ScheduleMeasurement {
            rate,
            workers: sender_ids,
            configurations,
            measurement_type: measurement_type as u32,
            unicast: is_unicast,
            ipv6: is_ipv6,
            divide: is_divide,
            interval,
            responsive: is_responsive,
            targets: Some(Targets { dst_list: ips }),
            record: dns_record.to_string(),
            url,
        };
        cli_client
            .do_measurement_to_server(
                measurement_definition,
                is_cli,
                is_shuffle,
                hitlist_path,
                hitlist_length,
                path,
                is_config,
                worker_map,
            )
            .await
    } else {
        panic!("Unrecognized command");
    }
}

impl CliClient {
    /// Perform a measurement at the orchestrator, await measurement results, and write them to a file.
    ///
    /// # Arguments
    ///
    /// * 'measurement_definition' - measurement definition created from the command-line arguments
    ///
    /// * 'is_cli' - boolean whether the results should be streamed to the CLI or not
    ///
    /// * 'is_shuffle' - boolean whether the hitlist should be shuffled or not
    ///
    /// * 'hitlist' - hitlist file path
    ///
    /// * 'hitlist_length' - length of hitlist (i.e., number of target addresses)
    ///
    /// * 'configurations' - specifies the source IP and ports to use for each worker
    ///
    /// * 'path' - optional path for output file (default is current directory)
    /// 
    /// * 'is_config' - boolean whether the measurement is configuration-based or not
    /// 
    /// * 'workers' - map of worker IDs to hostnames
    async fn do_measurement_to_server(
        &mut self,
        measurement_definition: ScheduleMeasurement,
        is_cli: bool,
        is_shuffle: bool,
        hitlist: &str,
        hitlist_length: usize,
        path: Option<&String>,
        is_config: bool,
        workers: HashMap<u32, String>,
    ) -> Result<(), Box<dyn Error>> {
        let is_divide = measurement_definition.divide;
        let is_ipv6 = measurement_definition.ipv6;
        let probing_rate = measurement_definition.rate;
        let measurement_type = measurement_definition.measurement_type;
        let is_unicast = measurement_definition.unicast;
        let interval = measurement_definition.interval;
        let origin_str = if is_unicast {
            measurement_definition
                .configurations
                .first()
                .and_then(|conf| conf.origin.as_ref()) // Use as_ref to borrow if Origin is not Copy
                .map(|origin| {
                    format!(
                        "Unicast (source port: {}, destination port: {})",
                        origin.sport, origin.dport
                    )
                }).expect("No unicast origin found")
        } else {
            if is_config {
                "Anycast configuration-based".to_string()
            } else {
                measurement_definition
                    .configurations
                    .first()
                    .and_then(|conf| conf.origin.as_ref())
                    .map(|origin| {
                        format!(
                            "Anycast (source IP: {}, source port: {}, destination port: {})",
                            origin.src.unwrap(), origin.sport, origin.dport
                        )
                    }).expect("No anycast origin found")
            }
        };

        // Get the u32s of the workers that are active
        let active_workers = if measurement_definition.workers.is_empty() {
            workers.keys().cloned().collect() // All workers are active
        } else {
            measurement_definition.workers.clone()
        };

        let measurement_length = if is_divide {
            ((hitlist_length as f32 / (probing_rate * active_workers.len() as u32) as f32) + 1.0)
                / 60.0
        } else {
            (((active_workers.len() as f32 - 1.0) * interval as f32) // Last worker starts probing
                + (hitlist_length as f32 / probing_rate as f32) // Time to probe all addresses
                + 1.0) // Time to wait for last replies
                / 60.0 // Convert to minutes
        };
        if is_divide {
            println!("[CLI] Divide-and-conquer enabled");
        }
        println!(
            "[CLI] This measurement will take an estimated {:.2} minutes",
            measurement_length
        );

        let response = self
            .grpc_client
            .do_measurement(Request::new(measurement_definition.clone()))
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
        let total_steps = (measurement_length * 60.0) as u64; // measurement_length in seconds
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
            for _ in 0..total_steps {
                if is_done_clone.load(Ordering::Relaxed) {
                    break;
                }
                pb.inc(1); // Increment the progress bar by one step
                tokio::time::sleep(Duration::from_secs(1)).await; // Simulate time taken for each step
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
        let type_str = match measurement_type {
            1 => "ICMP",
            2 => "UDP",
            3 => "TCP",
            4 => "UDP-CHAOS",
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
        let file_path = if path.is_some() {
            if path.unwrap().ends_with('/') {
                // user provided a path, use default naming convention for file
                format!(
                    "{}{}{}{}.csv.gz",
                    path.unwrap(),
                    filetype,
                    type_str,
                    timestamp_start_str
                )
            } else {
                // user provided a file (with possibly a path)
                format!("{}", path.unwrap())
            }
        } else {
            // write file to current directory using default naming convention
            format!("./{}{}{}.csv.gz", filetype, type_str, timestamp_start_str)
        };

        // Create the output file
        let file = File::create(file_path).expect("Unable to create file");

        let md_file = get_metadata(
            is_divide,
            origin_str,
            hitlist,
            is_shuffle,
            type_str,
            probing_rate,
            interval,
            timestamp_start_str,
            measurement_length,
            active_workers,
            &workers,
            &measurement_definition.configurations,
            is_config,
        );

        let is_multi_origin = if is_unicast {
            false
        } else {
            measurement_definition.configurations.len() > 1
        };

        // Start thread that writes results to file
        write_results(rx_r, is_cli, file, md_file, measurement_type, is_multi_origin);

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
        let channel = if fqdn.is_some() {
            // Secure connection
            let addr = format!("https://{}", address);

            // Load the CA certificate used to authenticate the orchestrator
            let pem = fs::read_to_string("tls/orchestrator.crt")
                .expect("Unable to read CA certificate at ./tls/orchestrator.crt");
            let ca = Certificate::from_pem(pem);

            let tls = ClientTlsConfig::new()
                .ca_certificate(ca)
                .domain_name(fqdn.unwrap());

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

/// Returns a vector of lines containing the metadata of the measurement
///
/// # Arguments
///
/// Variables describing the measurement
fn get_metadata(
    is_divide: bool,
    origin_str: String,
    hitlist: &str,
    is_shuffle: bool,
    type_str: String,
    probing_rate: u32,
    interval: u32,
    timestamp_start_str: String,
    expected_length: f32,
    active_workers: Vec<u32>,
    all_workers: &HashMap<u32, String>,
    configurations: &Vec<Configuration>,
    is_config: bool,
) -> Vec<String> {
    let mut md_file = Vec::new();
    if is_divide {
        md_file.push("# Divide-and-conquer measurement".to_string());
    }
    md_file.push(format!("# Origin used: {}", origin_str));
    md_file.push(
        format!(
            "# Hitlist{}: {}",
            if is_shuffle { " (shuffled)" } else { "" },
            hitlist
        )
    );
    md_file.push(format!("# Measurement type: {}", type_str));
    md_file.push(format!("# Probing rate: {}", probing_rate.with_separator()));
    md_file.push(format!("# Interval: {}", interval));
    md_file.push(format!("# Start measurement: {}", timestamp_start_str));
    md_file.push(
        format!(
            "# Expected measurement length (seconds): {:.6}",
            expected_length
        )
    );
    if active_workers.len() < all_workers.len() {
        md_file.push(
            format!(
                "# Selective probing using the following workers: {:?}",
                active_workers
            )
        );
    }
    md_file.push("# Connected workers:".to_string());
    for (id, hostname) in all_workers {
        md_file.push(format!("# \t * ID: {:<2}, hostname: {}", id, hostname))
    }

    // Write configurations used for the measurement
    if is_config {
        md_file.push("# Configurations:".to_string());
        for configuration in configurations {
            let origin = configuration.origin.unwrap();
            let src = origin.src.expect("Invalid source address");
            let worker_id = if configuration.worker_id == u32::MAX {
                "ALL".to_string()
            } else {
                configuration.worker_id.to_string()
            };
            md_file.push(
                format!(
                    "# \t * Worker ID: {:<2}, source IP: {}, source port: {}, destination port: {}",
                    worker_id,
                    src,
                    origin.sport,
                    origin.dport
                )
            );
        }

        if configurations.len() > 1 {
            md_file.push("# Multiple origins used".to_string());

            for configuration in configurations {
                let origin = configuration.origin.unwrap();
                let src = origin.src.expect("Invalid source address");

                let origin_id = origin.origin_id;

                md_file.push(format!("# \t * Origin ID: {:<2}, source IP: {}, source port: {}, destination port: {}", origin_id, src, origin.sport, origin.dport));
            }
        }
    }

    return md_file;
}

/// Writes the results to a file (and optionally to the command-line)
///
/// # Arguments
///
/// * 'rx' - The receiver channel that receives the results
///
/// * 'is_cli' - A boolean that determines whether the results should be printed to the command-line
///
/// * 'file' - The file to which the results should be written
/// 
/// * 'md_file' - Metadata for the measurement, to be written to the file
///
/// * 'measurement_type' - The type of measurement being performed
/// 
/// * is_multi_origin - A boolean that determines whether multiple origins are used
fn write_results(
    mut rx: UnboundedReceiver<TaskResult>,
    is_cli: bool,
    file: File,
    md_file: Vec<String>,
    measurement_type: u32,
    is_multi_origin: bool,
) {
    // CSV writer to command-line interface
    let mut wtr_cli = if is_cli {
        Some(Writer::from_writer(io::stdout()))
    } else {
        None
    };

    let buffered_file_writer = BufWriter::new(file);
    let mut gz_encoder = GzEncoder::new(buffered_file_writer, Compression::default());

    // Write metadata to file
    for line in &md_file {
        if let Err(e) = writeln!(gz_encoder, "{}", line) {
            eprintln!("Failed to write metadata line to Gzip stream: {}", e);
        }
    }

    // .gz writer
    let mut wtr_file = Writer::from_writer(gz_encoder);

    // Write header
    let header = get_header(measurement_type, is_multi_origin);
    // TODO write header to CLI
    if is_cli {
        wtr_cli
            .as_mut()
            .unwrap()
            .write_record(&header)
            .expect("Failed to write header to stdout")
        // TODO CLI should print more concise information
        // ip address instead of ip number
        // measured RTT instead of tx_time and rx_time
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
                let result = get_result(result, task_result.worker_id);

                // Write to command-line
                if is_cli {
                    if let Some(ref mut writer) = wtr_cli {
                        writer
                            .write_record(&result)
                            .expect("Failed to write payload to CLI");
                        writer.flush().expect("Failed to flush stdout");
                    }
                };

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
fn get_header(measurement_type: u32, is_multi_origin: bool) -> Vec<&'static str> {
    // Information available for all measurement types
    let mut header = vec!["rx_worker_id", "rx_time", "reply_src_addr", "ttl"];
    // Information specific to each measurement type
    header.append(&mut match measurement_type {
        1 => vec!["tx_time", "tx_worker_id"], // ICMP
        2 => vec!["tx_time", "tx_worker_id"], // UDP/DNS (A record)
        3 => vec!["seq"], // TCP
        4 => vec!["tx_worker_id", "chaos_data"], // UDP/DNS (CHAOS record)
        _ => panic!("Undefined type."),
    });

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
/// * `x_worker_id` - The worker ID of the receiver
fn get_result(result: Reply, rx_worker_id: u32) -> Vec<String> {
    let origin_id = result.origin_id.to_string();
    let is_multi_origin = result.origin_id != 0 && result.origin_id != u32::MAX;
    let rx_worker_id = rx_worker_id.to_string();
    let rx_time = result.rx_time.to_string();

    let ip_result = result.ip_result.unwrap();
    let reply_src = ip_result.get_src_str();
    let ttl = ip_result.ttl.to_string();

    let mut row = vec![rx_worker_id, rx_time, reply_src, ttl];
    match result.value.unwrap() {
        ResultPing(ping) => {
            row.push(ping.tx_time.to_string());
            row.push(ping.tx_worker_id.to_string());
        }
        ResultUdp(udp) => {
            // DNS reply
            match udp.value {
                Some(DnsARecord(dns_a_record)) => {
                    row.push(dns_a_record.tx_time.to_string());
                    row.push(dns_a_record.tx_worker_id.to_string());
                }
                Some(DnsChaos(dns_chaos)) => {
                    row.push(dns_chaos.tx_worker_id.to_string());
                    row.push(dns_chaos.chaos_data);
                }
                None => {
                    panic!("No payload found for UDP result!");
                }
            }
        }
        ResultTcp(tcp) => {
            row.push(tcp.seq.to_string());
        }
    }

    if is_multi_origin {
        row.push(origin_id);
    }

    return row;
}

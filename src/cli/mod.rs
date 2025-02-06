use std::{fs, io};
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{Datelike, Local, Timelike};
use clap::ArgMatches;
use csv::Writer;
use indicatif::{ProgressBar, ProgressStyle};
use prettytable::{Attr, Cell, color, format, Row, Table};
use rand::seq::SliceRandom;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tonic::Request;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};

use custom_module::{IP, Separated};
use custom_module::verfploeter::{
    Address, Configuration, controller_client::ControllerClient, Empty,
    Origin, ScheduleMeasurement, Targets, TaskResult,
    trace_result::Value, udp_payload::Value::DnsARecord,
    udp_payload::Value::DnsChaos,
    verfploeter_result::Value::Ping as ResultPing, verfploeter_result::Value::Tcp as ResultTcp,
    verfploeter_result::Value::Trace as ResultTrace, verfploeter_result::Value::Udp as ResultUdp, VerfploeterResult,
};

use crate::custom_module;

/// A CLI client that creates a connection with the 'orchestrator' and sends the desired commands based on the command-line input.
pub struct CliClient {
    grpc_client: ControllerClient<Channel>,
}

/// Connect to the orchestrator and make it perform the CLI command from the command-line
///
/// # Arguments
///
/// * 'args' - contains the parsed CLI arguments
#[tokio::main]
pub async fn execute(args: &ArgMatches) -> Result<(), Box<dyn Error>> {
    let server_address = args.value_of("orchestrator").unwrap();
    let fqdn = args.value_of("tls");

    // Connect with orchestrator
    println!("[CLI] Connecting to orchestrator - {}", server_address);
    let grpc_client = CliClient::connect(server_address, fqdn).await.expect("Unable to connect to orchestrator");
    let mut cli_client = CliClient { grpc_client };

    if args.subcommand_matches("worker-list").is_some() { // Perform the worker-list command
        cli_client.list_workers().await
    } else if let Some(matches) = args.subcommand_matches("start") { // Start a Verfploeter measurement
        // Source IP for the measurement
        let is_unicast = matches.is_present("UNICAST");
        let is_divide = matches.is_present("DIVIDE");
        let is_responsive = matches.is_present("RESPONSIVE");
        if is_responsive && is_divide {
            panic!("Responsive mode not supported for divide-and-conquer measurements");
        }

        // Get optional opt-out URL
        let url = if matches.is_present("URL") {
            matches.value_of("URL").unwrap().to_string()
        } else {
            "".to_string()
        };

        let src = if matches.is_present("ADDRESS") {
            Some(Address::from(matches.value_of("ADDRESS").unwrap().to_string()))
        } else {
            None
        };

        // Read the configuration file (unnecessary for unicast)
        let configurations = if matches.is_present("CONF") && !is_unicast {
            // if is_divide { panic!("Divide-and-conquer is currently unsupported for configuration based measurements.") }
            let conf_file = matches.value_of("CONF").unwrap();
            println!("[CLI] Using configuration file: {}", conf_file);
            let file = File::open(conf_file).unwrap_or_else(|_| panic!("Unable to open configuration file {}", conf_file));
            let buf_reader = BufReader::new(file);
            let configurations: Vec<Configuration> = buf_reader // Create a vector of addresses from the file
                .lines()
                .filter_map(|l| {
                    let line = l.expect("Unable to read configuration line");
                    if line.starts_with("#") { return None; } // Skip comments
                    let parts: Vec<&str> = line.split('-').map(|s| s.trim()).collect();
                    if parts.len() != 2 { panic!("Invalid configuration format: {}", line); }
                    let worker_id = if parts[0] == "ALL" { // All clients probe this configuration
                        u32::MAX
                    } else {
                        u32::from_str(parts[0]).expect("Unable to parse configuration worker ID")
                    };

                    // TODO allow for hostname as identifier
                    let addr_ports: Vec<&str> = parts[1].split(',').map(|s| s.trim()).collect();
                    if addr_ports.len() != 3 { panic!("Invalid configuration format: {}", line); }
                    let src = Address::from(addr_ports[0].to_string());
                    // Parse to u16 first, must fit in header
                    let sport = u16::from_str(addr_ports[1]).expect("Unable to parse source port");
                    let dport = u16::from_str(addr_ports[2]).expect("Unable to parse destination port");

                    Some(Configuration {
                        worker_id,
                        origin: Some(Origin {
                            src: Some(src),
                            sport: sport.into(),
                            dport: dport.into(),
                        }),
                    })
                })
                .collect();
            if configurations.len() == 0 {
                panic!("No valid configurations found in file {}", conf_file);
            }

            // Make sure all configurations have the same IP type
            let is_ipv6 = configurations.first().unwrap().origin.clone().unwrap().src.unwrap().is_v6();
            if configurations.iter().any(|conf| conf.origin.clone().unwrap().src.unwrap().is_v6() != is_ipv6) {
                panic!("Configurations are not all of the same type! (IPv4 & IPv6)");
            }
            Some(configurations)
        } else {
            None
        };

        // There must be a defined anycast source address, configuration, or unicast flag
        if src.is_none() && configurations.is_none() && !is_unicast {
            panic!("No source address or configuration file provided!");
        }

        // Get the target IP addresses
        let hitlist_path = matches.value_of("IP_FILE").expect("No hitlist file provided!");
        let file = File::open(hitlist_path).unwrap_or_else(|_| panic!("Unable to open file {}", hitlist_path));
        let buf_reader = BufReader::new(file);

        let mut ips: Vec<Address> = buf_reader // Create a vector of addresses from the file
            .lines()
            .map(|l| {
                Address::from(l.unwrap())
            })
            .collect();
        let is_ipv6 = ips.first().unwrap().is_v6();

        // Panic if the source IP is not the same type as the addresses
        if configurations.is_some() {
            if configurations.clone().unwrap().first().unwrap().origin.clone().unwrap().src.unwrap().is_v6() != is_ipv6 {
                panic!("Hitlist addresses are not the same type as the source addresses used! (IPv4 & IPv6)");
            }
        } else if src.is_some() && src.clone().unwrap().is_v6() != is_ipv6 {
            panic!("Source IP and target addresses are not of the same type! (IPv4 & IPv6)");
        }
        // Panic if the ips in the hitlist are not all the same type
        if ips.iter().any(|ip| ip.is_v6() != is_ipv6) {
            panic!("Hitlist addresses are not all of the same type! (mixed IPv4 & IPv6)");
        }

        // Shuffle the hitlist, if desired
        let shuffle = matches.is_present("SHUFFLE");
        if shuffle {
            let mut rng = rand::thread_rng();
            ips.as_mut_slice().shuffle(&mut rng);
        }

        // Get the clients that have to send out probes
        let client_ids = if matches.is_present("CLIENTS") {
            let clients_str = matches.value_of("CLIENTS").unwrap();
            clients_str.trim_matches(|c| c == '[' || c == ']')
                .split(',')
                .map(|id| u32::from_str(id.trim()).expect(&format!("Unable to parse worker ID: {:<2}", id)))
                .collect::<Vec<u32>>()
        } else {
            println!("[CLI] Probes will be sent out from all clients");
            Vec::new()
        };
        if client_ids.len() > 0 {
            println!("[CLI] Client-selective probing using the following clients: {:?}", client_ids); // TODO print worker hostnames
        }

        // Get the type of measurement
        let measurement_type = if let Ok(measurement_type) = u32::from_str(matches.value_of("TYPE").unwrap()) { measurement_type } else { panic!("Invalid measurement type! (can be either 1, 2, 3, or 4)") };
        // We only accept measurement types 1, 2, 3, 4
        if (measurement_type < 1) | (measurement_type > 4) { panic!("Invalid measurement type value! (can be either 1, 2, 3, or 4)") }

        // CHAOS value to send in the DNS query
        let dns_record = if measurement_type == 4 {
            if matches.is_present("HOSTNAME") {
                matches.value_of("HOSTNAME").unwrap()
            } else {
                "hostname.bind"
            }
        } else if measurement_type == 2 {
            if matches.is_present("HOSTNAME") {
                matches.value_of("HOSTNAME").unwrap()
            } else {
                "any.dnsjedi.org" // TODO what default record to use for A
            }
        } else {
            ""
        };

        // Origin for the measurement
        let origin = if configurations.is_none() {
            // Obtain port values (read as u16 as is the port header size)
            let sport = u16::from_str(matches.value_of("SOURCE_PORT").unwrap_or_else(|| "62321")).expect("Unable to parse source port") as u32;
            let dport = if matches.is_present("DESTINATION_PORT") {
                u16::from_str(matches.value_of("DESTINATION_PORT").unwrap()).expect("Unable to parse destination port") as u32
            } else {
                if measurement_type == 2 || measurement_type == 4 {
                    53 // Default DNS destination port
                } else {
                    63853 // Default destination port
                }
            };

            // configurations.unwrap().append(&mut vec![Configuration { // TODO use this instead of 'default' origin
            //     client_id: u32::MAX,
            //     origin: Some(Origin {
            //         source_address: source_ip,
            //         source_port,
            //         destination_port,
            //     })
            // }]);

            Some(Origin {
                src,
                sport,
                dport,
            })
        } else {
            None
        };

        // Check for command-line option that determines whether to stream to CLI
        let cli = matches.is_present("STREAM");
        let traceroute = matches.is_present("TRACEROUTE");

        // Get interval, rate. Default values are 1 and 1000 respectively
        let interval = u32::from_str(matches.value_of("INTERVAL").unwrap_or_else(|| "1")).expect("Unable to parse interval");
        let rate = u32::from_str(matches.value_of("RATE").unwrap_or_else(|| "1000")).expect("Unable to parse rate");

        let t_type = match measurement_type {
            1 => "ICMP/ping",
            2 => "UDP/DNS",
            3 => "TCP/SYN-ACK",
            4 => "UDP/CHAOS",
            _ => "Undefined (defaulting to ICMP/ping)"
        };
        let hitlist_length = ips.len();

        println!("[CLI] Performing {} measurement targeting {} addresses, with a rate of {}, and an interval of {}",
                 t_type,
                 hitlist_length.with_separator(),
                 rate.with_separator(),
                 interval
        );

        if is_responsive {
            println!("[CLI] Measurement will be performed in responsive mode (only probing responsive addresses, checked by the Server)");
        }

        // Print the origins used
        if is_unicast {
            if let Some(origin) = &origin {
                println!("[CLI] Clients send probes using their unicast source IP with source port: {}, destination port: {}",
                         origin.sport, origin.dport);
            }
        } else if configurations.is_some() {
            println!("[CLI] Clients send probes using the following configurations:");
            for configuration in configurations.clone().unwrap() {
                if let Some(origin) = &configuration.origin {
                    let src = IP::from(origin.src.clone().unwrap()).to_string();
                    let sport = origin.sport;
                    let dport = origin.dport;

                    if configuration.worker_id == u32::MAX {
                        println!(
                            "\t* All clients, source IP: {}, source port: {}, destination port: {}",
                            src, sport, dport
                        );
                    } else {
                        println!(
                            "\t* worker ID: {:<2}, source IP: {}, source port: {}, destination port: {}",
                            configuration.worker_id, src, sport, dport
                        );
                    }
                }
            }
        } else {
            if let Some(origin) = &origin {
                let src = IP::from(origin.src.clone().unwrap()).to_string();
                println!(
                    "[CLI] Clients send probes using the following origin: source IP: {}, source port: {}, destination port: {}",
                    src, origin.sport, origin.dport
                );
            }
        }

        // get optional path to write results to TODO ensure path is valid before measurement start
        let path = matches.value_of("OUT");
        if path.is_some() {
            // Make sure path is valid
            // Output file
            if path.unwrap().ends_with('/') {
                // User provided a path (check if path is valid)
                // TODO
            } else {
                // user provided a file (check if file is valid)
                // TODO
            };
        }

        // Create the measurement definition and send it to the orchestrator
        let measurement_definition = ScheduleMeasurement {
            rate,
            workers: client_ids,
            origin,
            configurations: configurations.clone().unwrap_or_default(), // default is empty vector
            measurement_type,
            unicast: is_unicast,
            ipv6: is_ipv6,
            traceroute,
            divide: is_divide,
            interval,
            responsive: is_responsive,
            targets: Some(Targets {
                dst_addresses: ips,
            }),
            record: dns_record.to_string(),
            url,
        };
        cli_client.do_measurement_to_server(measurement_definition, cli, shuffle, hitlist_path, hitlist_length, configurations.unwrap_or_default(), path).await
    } else {
        panic!("Unrecognized command");
    }
}

impl CliClient {
    /// Send the 'do_measurement' command to the orchestrator, await the measurement results, and print them out to command-line & file as CSV.
    ///
    /// # Arguments
    ///
    /// * 'measurement_definition' - the measurement that is being requested at the orchestrator (contains all the necessary information about the upcoming measurement)
    ///
    /// * 'cli' - a boolean that determines whether the results should be printed to the command-line (will be true if --stream was added to the start command)
    ///
    /// * 'shuffle' - a boolean whether the hitlist has been shuffled or not
    ///
    /// * 'hitlist' - the name of the hitlist file that was used for this measurement
    ///
    /// * 'hitlist_length' - the length of the hitlist
    ///
    /// * 'configurations' - a vector of configurations that are used for the measurement
    ///
    /// * 'path' - optional path to write the results to
    async fn do_measurement_to_server(
        &mut self,
        measurement_definition: ScheduleMeasurement,
        cli: bool,
        shuffle: bool,
        hitlist: &str,
        hitlist_length: usize,
        configurations: Vec<Configuration>,
        path: Option<&str>,
    ) -> Result<(), Box<dyn Error>> {
        let is_divide = measurement_definition.divide;
        let is_ipv6 = measurement_definition.ipv6;
        let rate = measurement_definition.rate;
        let measurement_type = measurement_definition.measurement_type;
        let is_unicast = measurement_definition.unicast;
        let is_traceroute = measurement_definition.traceroute;
        let interval = measurement_definition.interval;
        let origin = if is_unicast {
            let sport = measurement_definition.origin.clone().unwrap().sport;
            let dport = measurement_definition.origin.clone().unwrap().dport;
            format!("Unicast (source port: {}, destination port: {})", sport, dport)
        } else {
            if measurement_definition.clone().origin.is_some() {
                let src = IP::from(measurement_definition.clone().origin.unwrap().src.unwrap()).to_string();
                let sport = measurement_definition.origin.clone().unwrap().sport;
                let dport = measurement_definition.origin.clone().unwrap().dport;
                format!("Anycast (source IP: {}, source port: {}, destination port: {})", src, sport, dport)
            } else {
                "Anycast configuration-based".to_string()
            }
        };

        // Obtain connected worker information for metadata
        let response = self.grpc_client.list_workers(Request::new(Empty::default())).await.expect("Connection to orchestrator failed");
        let mut workers = HashMap::new();
        response.into_inner().workers.iter().for_each(|worker| {
            workers.insert(worker.worker_id, worker.metadata.clone().unwrap());
        });

        // TODO measurement length does not take into account that not all clients may participate
        let measurement_length = if is_divide {
            ((hitlist_length as f32 / (rate * workers.len() as u32) as f32) + 1.0) / 60.0
        } else if is_unicast {
            ((hitlist_length as f32 / rate as f32) // Time to probe all addresses
                + 1.0) // Time to wait for last replies
                / 60.0 // Convert to minutes
        } else {
            (((workers.len() as f32 - 1.0) * interval as f32) // Last worker starts probing
                + (hitlist_length as f32 / rate as f32) // Time to probe all addresses
                + 1.0) // Time to wait for last replies
                / 60.0 // Convert to minutes
        };
        if is_divide {
            println!("[CLI] This measurement will be divided among clients (each worker will probe a unique subset of the addresses)");
        }
        println!("[CLI] This measurement will take an estimated {:.2} minutes", measurement_length);

        let response = self.grpc_client.do_measurement(Request::new(measurement_definition.clone())).await;
        if let Err(e) = response {
            println!("[CLI] Server did not perform the measurement for reason: '{}'", e.message());
            return Err(Box::new(e));
        }
        let start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let timestamp_start = Local::now();
        let timestamp_start_str = format!("{:04}-{:02}-{:02}T{:02}_{:02}_{:02}",
                                          timestamp_start.year(), timestamp_start.month(), timestamp_start.day(),
                                          timestamp_start.hour(), timestamp_start.minute(), timestamp_start.second());
        println!("[CLI] Measurement started at {}", timestamp_start.format("%H:%M:%S"));

        // Progress bar
        let total_steps = (measurement_length * 60.0) as u64; // measurement_length in seconds
        let pb = ProgressBar::new(total_steps);
        pb.set_style(
            ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
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
        let mut stream = response.expect("Unable to obtain the orchestrator stream").into_inner();
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

        // Temporary output file (for writing live results to)
        let temp_file = File::create("manycastr_results_feed").expect("Unable to create file");

        // Start thread that writes results to file
        write_results(rx_r, cli, temp_file, measurement_type, is_traceroute);

        let mut replies_count = 0;
        while let Ok(Some(task_result)) = stream.message().await {
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
        println!("[CLI] Time of end measurement {}", Local::now().format("%H:%M:%S"));
        println!("[CLI] Number of replies captured: {}", replies_count.with_separator());

        // If the stream closed during a measurement
        if !graceful {
            tx_r.send(TaskResult::default()).unwrap(); // Let the results channel know that we are done
            println!("[CLI] Measurement ended prematurely!");
        }

        // Get current timestamp and create timestamp file encoding
        let timestamp_end = Local::now();
        let timestamp_end_str = format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
                                        timestamp_end.year(), timestamp_end.month(), timestamp_end.day(),
                                        timestamp_end.hour(), timestamp_end.minute(), timestamp_end.second());

        // Determine the type of measurement
        let measurement_type = if is_unicast {
            "GCD_"
        } else {
            "MAnycast_"
        };

        // Output file
        let file_path = if path.is_some() {
            if path.unwrap().ends_with('/') { // user provided a path, use default naming convention for file
                format!("{}{}{}{}.csv", path.unwrap(), measurement_type, type_str, timestamp_end_str)
            } else { // user provided a file (with possibly a path)
                format!("{}", path.unwrap())
            }
        } else { // write file to current directory using default naming convention
            format!("./{}{}{}.csv", measurement_type, type_str, timestamp_end_str)
        };

        // Create the output file
        let mut file = File::create(file_path.clone()).expect(format!("Unable to create file at {}", file_path).as_str());

        // Write metadata of measurement
        if !graceful {
            file.write_all(b"# Incomplete measurement\n")?;
        } else {
            file.write_all(b"# Completed measurement\n")?;
        }
        if is_divide { file.write_all(b"# Divide-and-conquer measurement\n")?; }
        file.write_all(format!("# Origin used: {}\n", origin).as_ref())?;
        if shuffle {
            file.write_all(format!("# Hitlist (shuffled): {}\n", hitlist).as_ref())?;
        } else {
            file.write_all(format!("# Hitlist: {}\n", hitlist).as_ref())?;
        }
        file.write_all(format!("# Measurement type: {}\n", type_str).as_ref())?;
        // file.write_all(format!("# Measurement ID: {}\n", ).as_ref())?;
        file.write_all(format!("# Probing rate: {}\n", rate.with_separator()).as_ref())?;
        file.write_all(format!("# Interval: {}\n", interval).as_ref())?;
        file.write_all(format!("# Start measurement: {}\n", timestamp_start_str).as_ref())?;
        file.write_all(format!("# End measurement: {}\n", timestamp_end_str).as_ref())?;
        file.write_all(format!("# Measurement length (seconds): {:.6}\n", length).as_ref())?;
        if !measurement_definition.workers.is_empty() {
            file.write_all(format!("# Selective probing using the following workers: {:?}\n", measurement_definition.workers).as_ref())?;
        }
        file.write_all(b"# Connected workers:\n")?;
        for (id, metadata) in &workers {
            file.write_all(format!("# \t * ID: {:<2}, hostname: {}\n", id, metadata.hostname).as_ref()).expect("Failed to write worker data");
        }

        // Write configurations used for the measurement
        if !configurations.is_empty() {
            file.write_all(b"# Configurations:\n")?;
            for configuration in configurations {
                let src = IP::from(configuration.origin.clone().unwrap().src.expect("Invalid source address")).to_string();
                let client_id = if configuration.worker_id == u32::MAX {
                    "ALL".to_string()
                } else {
                    configuration.worker_id.to_string()
                };
                file.write_all(format!("# \t * worker ID: {:<2}, source IP: {}, source port: {}, destination port: {}\n", client_id, src, configuration.origin.clone().unwrap().sport, configuration.origin.unwrap().dport).as_ref()).expect("Failed to write configuration data");
            }
        }

        file.flush().expect("Failed to flush file");

        tx_r.closed().await; // Wait for all results to be written to file

        // Output file
        let mut temp_file = File::open("manycastr_results_feed").expect("Unable to create file");

        io::copy(&mut temp_file, &mut file).expect("Unable to copy from temp to final"); // Copy live results to the output file
        fs::remove_file("manycastr_results_feed").expect("Unable to remove temp file");
        Ok(())
    }

    /// Connect to the orchestrator
    ///
    /// # Arguments
    ///
    /// * 'address' - the address of the orchestrator (e.g., 190.100.10.10:50051)
    ///
    /// * 'fqdn' - an optional string that contains the FQDN of the orchestrator certificate (if TLS is enabled)
    ///
    /// # Returns
    ///
    /// A Result containing the ControllerClient and a Boxed Error if the connection fails
    ///
    /// # Examples
    ///
    /// ```
    /// let worker = CliClient::connect("190.100.10.10:50051", true).await;
    /// ```
    ///
    /// # Panics
    ///
    /// If the connection fails
    ///
    /// # Remarks
    ///
    /// This function is async and should be awaited
    ///
    /// tls requires a certificate at ./tls/orchestrator.crt
    async fn connect(address: &str, fqdn: Option<&str>) -> Result<ControllerClient<Channel>, Box<dyn Error>> {
        let channel = if fqdn.is_some() {
            // Secure connection
            let addr = format!("https://{}", address);

            // Load the CA certificate used to authenticate the orchestrator
            let pem = fs::read_to_string("tls/orchestrator.crt").expect("Unable to read CA certificate at ./tls/orchestrator.crt");
            let ca = Certificate::from_pem(pem);

            let tls = ClientTlsConfig::new()
                .ca_certificate(ca)
                .domain_name(fqdn.unwrap());

            let builder = Channel::from_shared(addr.to_owned())?; // Use the address provided
            builder
                .tls_config(tls).expect("Unable to set TLS configuration")
                .connect().await.expect("Unable to connect to orchestrator")
        } else {
            // Unsecure connection
            let addr = format!("http://{}", address);

            Channel::from_shared(addr.to_owned()).expect("Unable to set address")
                .connect().await.expect("Unable to connect to orchestrator")
        };
        // Create worker with secret token that is used to authenticate worker commands.
        let client = ControllerClient::new(channel);

        Ok(client)
    }

    /// Sends a list worker command to the orchestrator, awaits the result, and prints it to command-line.
    async fn list_workers(&mut self) -> Result<(), Box<dyn Error>> {
        println!("[CLI] Requesting workers list from orchestrator");
        let request = Request::new(Empty::default());
        let response = self.grpc_client.list_workers(request).await.expect("Connection to orchestrator failed");

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
        ]));

        for worker in response.into_inner().workers {
            table.add_row(prettytable::row!(
                    worker.metadata.clone().unwrap().hostname,
                    worker.worker_id,
                ));
        }
        table.printstd();

        Ok(())
    }
}

/// Write the results to the command-line interface and a file
///
/// # Arguments
///
/// * 'rx' - Receives task results to be written
///
/// * 'cli' - A boolean that determines whether the results should be printed to the command-line
///
/// * 'file' - The file to which the results should be written
///
/// * 'measurement_type' - The type of measurement being performed
///
/// * 'traceroute' - If true, it will handle traceroute results (which are written to a separate file)
fn write_results(
    mut rx: UnboundedReceiver<TaskResult>,
    cli: bool,
    file: File,
    measurement_type: u32,
    traceroute: bool,
) {
    // CSV writer to command-line interface
    let mut wtr_cli = if cli { Some(Writer::from_writer(io::stdout())) } else { None };
    // Traceroute writer
    let mut wtr_file_traceroute = if traceroute {
        let mut wtr_file = Writer::from_writer(File::create(format!("./out/traceroute.csv")).expect("Unable to create traceroute file"));  // TODO file name
        // Write header
        wtr_file.write_record(vec!["rx_worker_id", "reply_src_addr", "reply_dest_addr", "ttl", "rx_time", "tx_time", "tx_worker_id", "reply_src_port", "reply_dest_port", "seq", "ack"]).expect("Failed to write traceroute header");
        Some(wtr_file)
    } else {
        None
    };

    // Results file
    let mut wtr_file = Writer::from_writer(file);

    // Write header
    let header = get_header(measurement_type);
    if cli { wtr_cli.as_mut().unwrap().write_record(header.clone()).expect("Failed to write header to stdout") };
    wtr_file.write_record(header).expect("Failed to write header to file");

    tokio::spawn(async move {
        // Receive tasks from the outbound channel
        while let Some(task_result) = rx.recv().await {
            if task_result == TaskResult::default() {
                break;
            }

            let verfploeter_results: Vec<VerfploeterResult> = task_result.result_list;
            for result in verfploeter_results {
                let trace_result = match result.clone().value.unwrap() {
                    ResultTrace(_) => true,
                    _ => false
                };
                let result = get_result(result, task_result.worker_id, measurement_type);
                if cli {
                    if let Some(ref mut writer) = wtr_cli {
                        writer.write_record(result.clone()).expect("Failed to write payload to CLI");
                        writer.flush().expect("Failed to flush stdout");
                    }
                };
                // Traceroute results get written to a separate file
                if trace_result {
                    if let Some(ref mut writer) = wtr_file_traceroute {
                        writer.write_record(result.clone()).expect("Failed to write payload to traceroute");
                        writer.flush().expect("Failed to flush traceroute file");
                    }
                } else {
                    wtr_file.write_record(result).expect("Failed to write payload to file");
                }
            }
            wtr_file.flush().expect("Failed to flush file");
        }
        rx.close();
    });
}

/// Creates the appropriate header for the results file (based on the measurement type)
fn get_header(measurement_type: u32) -> Vec<&'static str> {
    // Information contained in TaskResult
    let mut header = vec!["rx_worker_id"];
    // Information contained in IPv4 header
    header.append(&mut vec!["reply_src_addr", "reply_dst_addr", "ttl"]);
    header.append(&mut match measurement_type {
        1 => vec!["rx_time", "tx_time", "probe_src_addr", "probe_dst_addr", "tx_worker_id"], // ICMP
        2 => vec!["rx_time", "reply_src_port", "reply_dst_port", "code", "tx_time", "probe_src_addr", "probe_dst_addr", "tx_worker_id", "probe_src_port", "probe_dst_port"], // UDP/DNS
        3 => vec!["rx_time", "reply_src_port", "reply_dst_port", "seq", "ack"], // TCP
        4 => vec!["rx_time", "reply_src_port", "reply_dst_port", "code", "tx_worker_id", "chaos_data"], // UDP/CHAOS
        _ => panic!("Undefined type.")
    });

    header
}

/// Get the result (csv row) from a VerfploeterResult message
///
/// # Arguments
///
/// * 'result' - The VerfploeterResult that is being written to this row
///
/// * 'rx_worker_id' - The worker ID of the receiver
///
/// * 'measurement_type' - The type of measurement being performed
fn get_result(
    result: VerfploeterResult,
    rx_worker_id: u32,
    measurement_type: u32,
) -> Vec<String> {
    match result.value.unwrap() {
        ResultTrace(trace) => {
            let ip_result = trace.ip_result.unwrap();
            let source_mb = ip_result.get_src_str();
            let ttl = trace.ttl;
            let rx_time = trace.rx_time.to_string();
            let tx_time = trace.tx_time.to_string();
            let tx_worker_id = trace.tx_worker_id.to_string();

            return match trace.value.unwrap() {
                Value::Ping(ping) => {
                    let inner_ip = ping.ip_result.unwrap();
                    let source = inner_ip.get_src_str();
                    let destination = inner_ip.get_dst_str();

                    vec![rx_worker_id.to_string(), source, destination, ttl.to_string(), source_mb, tx_worker_id, rx_time, tx_time]
                }
                Value::Udp(udp) => {
                    let inner_ip = udp.ip_result.unwrap();
                    let src = inner_ip.get_src_str();
                    let dst = inner_ip.get_dst_str();
                    let sport = udp.sport.to_string();
                    let dport = udp.dport.to_string();

                    vec![rx_worker_id.to_string(), src, dst, ttl.to_string(), source_mb, tx_worker_id, rx_time, tx_time, sport, dport]
                }
                Value::Tcp(tcp) => {
                    let inner_ip = tcp.ip_result.unwrap();
                    let src = inner_ip.get_src_str();
                    let dst = inner_ip.get_dst_str();
                    let sport = tcp.sport.to_string();
                    let dport = tcp.dport.to_string();
                    let seq = tcp.seq.to_string();
                    let ack = tcp.ack.to_string();

                    vec![rx_worker_id.to_string(), src, dst, ttl.to_string(), source_mb, tx_worker_id, rx_time, tx_time, sport, dport, seq, ack]
                },
            };
        }
        ResultPing(ping) => {
            let rx_time = ping.rx_time.to_string();

            let ip_result = ping.ip_result.unwrap();
            let reply_src = ip_result.get_src_str();
            let reply_dst = ip_result.get_dst_str();
            let ttl = ip_result.ttl.to_string();

            // Ping payload
            let payload = ping.payload.unwrap();
            let tx_time = payload.tx_time.to_string();
            let probe_src = payload.src.unwrap().to_string();
            let probe_dst = payload.dst.unwrap().to_string();
            let tx_worker_id = payload.tx_worker_id.to_string();

            return vec![rx_worker_id.to_string(), reply_src, reply_dst, ttl, rx_time, tx_time, probe_src, probe_dst, tx_worker_id];
        }
        ResultUdp(udp) => {
            let rx_time = udp.rx_time.to_string();
            let reply_sport = udp.sport.to_string();
            let reply_dport = udp.dport.to_string();
            let reply_code = udp.code.to_string();

            let ip_result = udp.ip_result.unwrap();
            let reply_src = ip_result.get_src_str();
            let reply_dst = ip_result.get_dst_str();
            let ttl = ip_result.ttl.to_string();

            if udp.payload == None { // ICMP reply
                if measurement_type == 2 {
                    let tx_time = "-1".to_string();
                    let probe_src = "-1".to_string();
                    let probe_dst = "-1".to_string();
                    let tx_worker_id = "-1".to_string();
                    let probe_sport = "-1".to_string();
                    let probe_dport = "-1".to_string();

                    return vec![rx_worker_id.to_string(), reply_src, reply_dst, ttl, rx_time, reply_sport, reply_dport, reply_code, tx_time, probe_src, probe_dst, tx_worker_id, probe_sport, probe_dport];
                } else if measurement_type == 4 {
                    let tx_worker_id = "-1".to_string();
                    let chaos = "-1".to_string();

                    return vec![rx_worker_id.to_string(), reply_src, reply_dst, ttl, rx_time, reply_sport, reply_dport, reply_code, tx_worker_id, chaos];
                } else {
                    panic!("No payload found for unexpected UDP result!");
                }
            }

            let payload = udp.payload.expect("No payload found for UDP result!");

            match payload.value {
                Some(DnsARecord(dns_a_record)) => {
                    let tx_time = dns_a_record.tx_time.to_string();
                    // IP::from(payload.source_address.unwrap()).to_string()
                    let probe_src = dns_a_record.src.unwrap().to_string();
                    let probe_dst = dns_a_record.dst.unwrap().to_string();
                    let tx_worker_id = dns_a_record.tx_worker_id.to_string();
                    let probe_sport = dns_a_record.sport.to_string();
                    let probe_dport = "53".to_string();

                    return vec![rx_worker_id.to_string(), reply_src, reply_dst, ttl, rx_time, reply_sport, reply_dport, reply_code, tx_time, probe_src, probe_dst, tx_worker_id, probe_sport, probe_dport];
                }
                Some(DnsChaos(dns_chaos)) => {
                    let tx_worker_id = dns_chaos.tx_worker_id.to_string();
                    let chaos = dns_chaos.chaos_data;

                    return vec![rx_worker_id.to_string(), reply_src, reply_dst, ttl, rx_time, reply_sport, reply_dport, reply_code, tx_worker_id, chaos];
                }
                None => {
                    panic!("No payload found for UDP result!");
                }
            }
        }
        ResultTcp(tcp) => {
            let rx_time = tcp.rx_time.to_string();
            let ip_result = tcp.ip_result.unwrap();
            let reply_src = ip_result.get_src_str();
            let reply_dst = ip_result.get_dst_str();
            let ttl = ip_result.ttl.to_string();
            let reply_sport = tcp.sport.to_string();
            let reply_dport = tcp.dport.to_string();
            let seq = tcp.seq.to_string();
            let ack = tcp.ack.to_string();

            return vec![rx_worker_id.to_string(), reply_src, reply_dst, ttl, rx_time, reply_sport, reply_dport, seq, ack];
        },
    }
}

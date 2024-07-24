use std::collections::HashMap;
use std::error::Error;
use rand::seq::SliceRandom;
use std::fs::File;
use std::{fs, io};
use std::io::{BufRead, BufReader, Write};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use chrono::{Datelike, Local, Timelike};
use clap::ArgMatches;
use prettytable::{Attr, Cell, color, format, Row, Table};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tonic::Request;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use csv::Writer;

use crate::custom_module;
use custom_module::IP;
use custom_module::verfploeter::{
    VerfploeterResult, controller_client::ControllerClient, TaskResult, ScheduleTask,
    schedule_task, Ping, Udp, Tcp, Empty, Address, verfploeter_result::Value::Ping as ResultPing,
    verfploeter_result::Value::Udp as ResultUdp, verfploeter_result::Value::Tcp as ResultTcp,
    verfploeter_result::Value::Trace as ResultTrace,
    udp_payload::Value::DnsARecord, udp_payload::Value::DnsChaos
};
use crate::custom_module::verfploeter::trace_result::Value;

/// A CLI client that creates a connection with the 'server' and sends the desired commands based on the command-line input.
pub struct CliClient {
    grpc_client: ControllerClient<Channel>,
}

/// Connect to the server and make it perform the CLI command from the command-line
///
/// # Arguments
///
/// * 'args' - contains the parsed CLI arguments
#[tokio::main]
pub async fn execute(args: &ArgMatches) -> Result<(), Box<dyn Error>> {
    let addr = args.value_of("server").unwrap();
    let tls = args.is_present("tls");

    // Create client connection with the Controller Server
    print!("[CLI] Connecting to Controller Server at address {} ... ", addr);
    let grpc_client = CliClient::connect(addr, tls).await.expect("Unable to connect to server");
    println!("Success"); // TODO unsuccessful connection is unclear
    let mut cli_client = CliClient { grpc_client, };

    if args.subcommand_matches("client-list").is_some() { // Perform the client-list command
        cli_client.list_clients_to_server().await
    } else if let Some(matches) = args.subcommand_matches("start") { // Start a Verfploeter measurement
        // Source IP for the measurement
        let source_ip = IP::from(matches.value_of("SOURCE_IP").unwrap().to_string());

        // Get the target IP addresses
        let ip_file = matches.value_of("IP_FILE").unwrap();
        let file = File::open(ip_file).unwrap_or_else(|_| panic!("Unable to open file {}", ip_file));
        let buf_reader = BufReader::new(file);
        let mut ips: Vec<Address> = buf_reader // Create a vector of addresses from the file
            .lines()
            .map(|l| {
                Address::from(IP::from(l.unwrap()))
            })
            .collect::<Vec<_>>();
        let ipv6 = ips.first().unwrap().is_v6();

        // Panic if the source IP is not the same type as the addresses
        if source_ip.is_v6() != ipv6 {
            panic!("Source IP and target addresses are not of the same type! (IPv4/IPv6)");
        }

        // Panic if the ips are not all the same type
        if ips.iter().any(|ip| ip.is_v6() != ipv6) {
            panic!("Target addresses are not all of the same type! (IPv4/IPv6)");
        }

        debug!("Loaded [{}] IP addresses on _ips vector", ips.len());

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
                .map(|id| u32::from_str(id.trim()).expect(&format!("Unable to parse client ID: {}", id)))
                .collect::<Vec<u32>>()
        } else {
            println!("[CLI] Probes will be sent out from all clients");
            Vec::new()
        };
        if client_ids.len() > 0 {
            println!("[CLI] Probes will be sent out from these clients: {:?}", client_ids);
            // TODO print client information
        }
        // let client_ids = if matches.is_present("CLIENTS") {
        //     let client_ids: Vec<u32> = matches.values_of("CLIENTS").unwrap()
        //         .map(|id| u32::from_str(id).expect(&format!("Unable to parse client ID: {}", id)))
        //         .collect();
        //
        //     println!("[CLI] Probes will be sent out from these clients: {:?}", client_ids);
        //     client_ids
        // } else {
        //     println!("[CLI] Probes will be sent out from all clients");
        //     vec![]
        // };

        // Get the type of task
        let task_type = if let Ok(task_type) = u32::from_str(matches.value_of("TYPE").unwrap()) { task_type } else { panic!("Invalid task type! (can be either 1, 2, 3, or 4)") };
        // We only accept task types 1, 2, 3, 4
        if (task_type < 1) | (task_type > 4) { panic!("Invalid task type value! (can be either 1, 2, 3, or 4)") }
        // Check for command-line option that determines whether to stream to CLI
        let cli = matches.is_present("STREAM");
        let unicast = matches.is_present("UNICAST");
        let traceroute = matches.is_present("TRACEROUTE");
        let divide = matches.is_present("DIVIDE");
        // Divide-and-conquer is only supported for anycast-based measurements
        if divide && unicast {
            panic!("Divide-and-conquer is only supported for anycast-based measurements");
        }

        // Get interval, rate. Default values are 1 and 1000 respectively
        let interval = u32::from_str(matches.value_of("INTERVAL").unwrap_or_else(|| "1")).unwrap();
        let rate = u32::from_str(matches.value_of("RATE").unwrap_or_else(|| "1000")).unwrap();

        let t_type = match task_type {
            1 => "ICMP/ping",
            2 => "UDP/DNS",
            3 => "TCP/SYN-ACK",
            4 => "UDP/CHAOS",
            _ => "Undefined (defaulting to ICMP/ping)"
        };

        println!("[CLI] Performing {} task targeting {} addresses, from source {}, with a rate of {}, and an interval of {}",
                 t_type,
                 ips.len().to_string()
                     .as_bytes()
                     .rchunks(3)
                     .rev()
                     .map(std::str::from_utf8)
                     .collect::<Result<Vec<&str>, _>>()
                     .expect("Unable to format hitlist length")
                     .join(","),
                 source_ip.to_string(),
                 rate.to_string().as_bytes()
                     .rchunks(3)
                     .rev()
                     .map(std::str::from_utf8)
                     .collect::<Result<Vec<&str>, _>>()
                     .expect("Unable to format rate")
                     .join(","),
            interval
        );

        let hitlist_length = ips.len();
        // Create the task and send it to the server
        let schedule_task = create_schedule_task(source_ip, ips, task_type, rate, client_ids, unicast, ipv6, divide, interval, traceroute);
        cli_client.do_task_to_server(schedule_task, cli, shuffle, ip_file, divide, hitlist_length).await
    } else {
        panic!("Unrecognized command");
    }
}

/// Create a Verfploeter ScheduleTask message that can be sent to the server.
///
/// # Arguments
///
/// * 'source_address' - the source address to be used for this task (will be overwritten by the clients if they have a source address specified locally)
///
/// * 'destination_addresses' - a vector of destination addresses that will be probed in this task (e.g., the hitlist)
///
/// * 'task_type' - the type of task, can be 1: ICMP/ping, 2: UDP/A, 3: TCP, 4: UDP/CHAOS
///
/// * 'rate' - the rate (packets / second) at which clients will send out probes (default: 1000)
///
/// * 'client_ids' - the list of clients (by IDs) who participate in the measurement (empty list means all clients participate)
///
/// * 'unicast' - a boolean that determines whether the clients must use their unicast source address
///
/// * 'ipv6' - a boolean that determines whether the addresses are IPv6 or not // TODO useless ?
///
/// * 'traceroute' - a boolean that determines whether the clients must perform traceroute measurements
/// # Examples
///
/// ```
/// let task = create_schedule_task(124.0.0.0, vec![1.1.1.1, 8.8.8.8], 1, 1400, vec![]);
/// ```
fn create_schedule_task(
    source_address: IP,
    destination_addresses: Vec<Address>,
    task_type: u32,
    rate: u32,
    client_ids: Vec<u32>,
    unicast: bool,
    ipv6: bool,
    divide: bool,
    interval: u32,
    traceroute: bool
) -> ScheduleTask {
    match task_type {
        1 => { // ICMP
            return ScheduleTask {
                rate,
                clients: client_ids,
                source_address: Some(Address::from(source_address)),
                task_type,
                unicast,
                ipv6,
                traceroute,
                divide,
                interval,
                data: Some(schedule_task::Data::Ping(Ping {
                    destination_addresses,
                }))
            }
        }
        2 | 4 => { // UDP
            return ScheduleTask {
                rate,
                clients: client_ids,
                source_address: Some(Address::from(source_address)),
                task_type,
                unicast,
                ipv6,
                traceroute,
                divide,
                interval,
                data: Some(schedule_task::Data::Udp(Udp {
                    destination_addresses,
                }))
            }
        }
        3 => { // TCP
            return ScheduleTask {
                rate,
                clients: client_ids,
                source_address: Some(Address::from(source_address)),
                task_type,
                unicast,
                ipv6,
                traceroute,
                divide,
                interval,
                data: Some(schedule_task::Data::Tcp(Tcp {
                    destination_addresses,
                }))
            }
        }
        _ => panic!("Undefined type.")
    }
}

impl CliClient {
    /// Send the 'do_task' command to the server, await the task results, and print them out to command-line & file as CSV.
    ///
    /// # Arguments
    ///
    /// * 'task' - the task that is being sent to the server (contains all the necessary information about the upcoming measurement)
    ///
    /// * 'cli' - a boolean that determines whether the results should be printed to the command-line (will be true if --stream was added to the start command)
    ///
    /// * 'shuffle' - a boolean whether the hitlist has been shuffled or not
    ///
    /// * 'hitlist' - the name of the hitlist file that was used for this measurement
    ///
    async fn do_task_to_server(
        &mut self,
        task: ScheduleTask,
        cli: bool,
        shuffle: bool,
        hitlist: &str,
        divide: bool,
        hitlist_length: usize,
    ) -> Result<(), Box<dyn Error>> {
        let rate = task.rate;
        let source_address = IP::from(task.clone().source_address.unwrap());
        let ipv6 = source_address.is_v6();
        let source_address = source_address.to_string();
        let task_type = task.task_type;
        let unicast = task.unicast;
        let traceroute = task.traceroute;

        // Obtain connected client information for metadata
        let request = Request::new(Empty::default());
        let response = self.grpc_client.list_clients(request).await.expect("Connection to server failed");
        let mut clients = HashMap::new();
        for client in response.into_inner().clients {
            clients.insert(client.client_id, client.metadata.clone().unwrap());
        }

        if divide {
            println!("[CLI] This task will be divided among clients (each client will probe a unique subset of the addresses)");
            println!("[CLI] This task will take an estimated {:.2} minutes", ((hitlist_length as f32 / (rate * clients.len() as u32) as f32) + 10.0) / 60.0);
        } else {
            println!("[CLI] This task will take an estimated {:.2} minutes", ((hitlist_length as f32 / rate as f32) + 10.0) / 60.0);
        }

        let request = Request::new(task.clone());
        println!("[CLI] Sending do_task to server");
        let response = self.grpc_client.do_task(request).await;
        if let Err(e) = response {
            println!("[CLI] Server did not perform the task for reason: '{}'", e.message());
            return Err(Box::new(e))
        }
        let start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let timestamp_start = Local::now();
        let timestamp_start_str = format!("{:04}-{:02}-{:02}T{:02};{:02};{:02}",
                                          timestamp_start.year(), timestamp_start.month(), timestamp_start.day(),
                                          timestamp_start.hour(), timestamp_start.minute(), timestamp_start.second());

        println!("[CLI] Task sent to server, awaiting results\n[CLI] Time of start measurement {}", timestamp_start.format("%H:%M:%S"));

        let mut graceful = false; // Will be set to true if the stream closes gracefully
        // Obtain the Stream from the server and read from it
        let mut stream = response.expect("Unable to obtain the server stream").into_inner();
        // Channel for writing results to file
        let (tx_r, rx_r) = unbounded_channel();

        // Get task type
        let type_str = match task_type {
            1 => "ICMP",
            2 => "UDP",
            3 => "TCP",
            4 => "UDP-CHAOS",
            _ => "ICMP",
        };
        let type_str = if ipv6 {
            format!("{}v6", type_str)
        } else {
            format!("{}v4", type_str)
        };

        // Temporary output file (for writing live results to)
        let temp_file = File::create("temp").expect("Unable to create file");

        // Start thread that writes results to file
        write_results(rx_r, cli, temp_file, task_type, traceroute);

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

        let end = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let length = (end - start) as f64 / 1_000_000_000.0; // Measurement length in seconds
        println!("[CLI] Waited {:.6} seconds for results.", length);
        println!("[CLI] Time of end measurement {}", Local::now().format("%H:%M:%S"));
        println!("[CLI] Number of replies captured: {}", replies_count);

        // If the stream closed during a measurement
        if !graceful { println!("[CLI] Measurement ended prematurely!"); }


        // Get current timestamp and create timestamp file encoding
        let timestamp_end = Local::now();
        let timestamp_end_str = format!("{:04}-{:02}-{:02}T{:02}_{:02}_{:02}",
                                        timestamp_end.year(), timestamp_end.month(), timestamp_end.day(),
                                        timestamp_end.hour(), timestamp_end.minute(), timestamp_end.second());

        // Determine the type of measurement
        let measurement_type = if unicast {
            "iGreedy"
        } else {
            "MAnycast"
        };

        // Output file // TODO add option to write as a compressed file
        let mut file = File::create(format!("./out/{}{}{}.csv", measurement_type, type_str, timestamp_end_str)).expect("Unable to create file");


        // Write metadata of measurement
        if !graceful {
            file.write_all(b"# Incomplete measurement\n")?;
        } else {
            file.write_all(b"# Completed measurement\n")?;
        }
        if unicast {
            file.write_all("# Default source address: Unicast\n".as_ref())?;
        } else {
            file.write_all(format!("# Default source address: {}\n", source_address).as_ref())?;
        }
        if shuffle {
            file.write_all(format!("# Hitlist (shuffled): {}\n", hitlist).as_ref())?;
        } else {
            file.write_all(format!("# Hitlist: {}\n", hitlist).as_ref())?;
        }
        file.write_all(format!("# Task type: {}\n", type_str).as_ref())?;
        // file.write_all(format!("# Task ID: {}\n", results[0].task_id).as_ref())?;
        file.write_all(format!("# Probing rate: {}\n", rate).as_ref())?;
        file.write_all(format!("# Start measurement: {}\n", timestamp_start_str).as_ref())?;
        file.write_all(format!("# End measurement: {}\n", timestamp_end_str).as_ref())?;
        file.write_all(format!("# Measurement length (seconds): {:.6}\n", length).as_ref())?;
        if task.clients.is_empty() {
            file.write_all(b"# Clients that are probing: all\n")?;
        } else {
            file.write_all(format!("# Clients that are probing: {:?}\n", task.clients).as_ref())?;
        }
        file.write_all(b"# Connected clients:\n")?;
        for (id, metadata) in &clients {
            let source_addr = IP::from(metadata.origin.clone().unwrap().source_address.expect("Invalid source address")).to_string();
            file.write_all(format!("# \t * ID: {}, hostname: {}, source IP: {}, source port: {}\n", id, metadata.hostname, source_addr, metadata.origin.clone().unwrap().source_port).as_ref()).expect("Failed to write client data");
        }

        file.flush()?;

        tx_r.closed().await; // Wait for all results to be written to file

        // Output file
        let mut temp_file = File::open("temp").expect("Unable to create file");

        io::copy(&mut temp_file, &mut file).expect("Unable to copy from temp to final"); // Copy live results to the output file
        fs::remove_file("temp").expect("Unable to remove temp file");
        Ok(())
    }

    /// Connect to the server
    ///
    /// # Arguments
    ///
    /// * 'address' - the address of the server (e.g., 190.100.10.10:50051)
    ///
    /// * 'tls' - a boolean that determines whether the connection should be secure or not
    ///
    /// # Returns
    ///
    /// A Result containing the ControllerClient and a Boxed Error if the connection fails
    ///
    /// # Examples
    ///
    /// ```
    /// let client = CliClient::connect("190.100.10.10:50051", true).await;
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
    /// tls requires a certificate at ./tls/server.crt
    async fn connect(address: &str, tls: bool) -> Result<ControllerClient<Channel>, Box<dyn Error>> {
        let channel = if tls {
            // Secure connection
            let addr = format!("https://{}", address);

            // Load the CA certificate used to authenticate the server
            let pem = fs::read_to_string("tls/server.crt").expect("Unable to read CA certificate at ./tls/server.crt");
            let ca = Certificate::from_pem(pem);

            let tls = ClientTlsConfig::new()
                .ca_certificate(ca)
                .domain_name("localhost");

            let builder = Channel::from_shared(addr.to_owned())?; // Use the address provided
            builder
                .tls_config(tls).expect("Unable to set TLS configuration")
                .connect().await.expect("Unable to connect to server")
        } else {
            // Unsecure connection
            let addr = format!("http://{}", address);

            Channel::from_shared(addr.to_owned()).expect("Unable to set address")
                .connect().await.expect("Unable to connect to server")
        };
        // Create client with secret token that is used to authenticate client commands.
        let client = ControllerClient::new(channel);

        Ok(client)
    }

    /// Sends a list clients command to the server, awaits the result, and prints it to command-line.
    async fn list_clients_to_server(&mut self) -> Result<(), Box<dyn Error>> {
        println!("[CLI] Sending list clients to server");
        let request = Request::new(Empty::default());
        let response = self.grpc_client.list_clients(request).await.expect("Connection to server failed");

        // Pretty print to command-line
        let mut table = Table::new();
        table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
        table.add_row(Row::new(vec![
            Cell::new("Hostname")
                .with_style(Attr::Bold)
                .with_style(Attr::ForegroundColor(color::GREEN)),
            Cell::new("Client ID")
                .with_style(Attr::Bold)
                .with_style(Attr::ForegroundColor(color::GREEN)),
            Cell::new("Source address")
                .with_style(Attr::Bold)
                .with_style(Attr::ForegroundColor(color::GREEN)),
            Cell::new("Source port")
                .with_style(Attr::Bold)
                .with_style(Attr::ForegroundColor(color::GREEN)),
            Cell::new("Destination port")
                .with_style(Attr::Bold)
                .with_style(Attr::ForegroundColor(color::GREEN)),
        ]));
        for client in response.into_inner().clients {
            let ip  = if client.metadata.clone().unwrap().origin.clone().unwrap().source_address.is_some() {
                IP::from(client.metadata.clone().unwrap().origin.unwrap().source_address.unwrap()).to_string()
            } else {
                "Default".to_string()
            };
            table.add_row(prettytable::row!(
                    client.metadata.clone().unwrap().hostname,
                    client.client_id,
                    ip, // Source address of this client
                    client.metadata.clone().unwrap().origin.unwrap().source_port, // Source port of this client
                    client.metadata.unwrap().origin.unwrap().destination_port // Destination port of this client
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
/// * 'task_type' - The type of task that was performed (determines the header)
///
/// * 'traceroute' - If true, it will handle traceroute results (which are written to a separate file)
fn write_results(
    mut rx: UnboundedReceiver<TaskResult>,
    cli: bool,
    file: File,
    task_type: u32,
    traceroute: bool
) {
    // CSV writer to command-line interface
    let mut wtr_cli = if cli { Some(Writer::from_writer(io::stdout())) } else { None };
    // Traceroute writer
    let mut wtr_file_traceroute = if traceroute { Some(Writer::from_writer(File::create(format!("./out/traceroute.csv")).expect("Unable to create traceroute file"))) } else { None }; // TODO file name

    // TODO write traceroute header

    // Results file
    let mut wtr_file = Writer::from_writer(file);

    // Write header
    let header = get_header(task_type);
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
                let result = get_result(result, task_result.client_id, task_type);
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

/// Creates the appropriate header for the results file (based on the task type)
fn get_header(task_type: u32) -> Vec<&'static str> {
    // Information contained in TaskResult
    let mut header = vec!["recv_client_id"];
    // Information contained in IPv4 header
    header.append(&mut vec!["reply_src_addr", "reply_dest_addr", "ttl"]);
    header.append(&mut match task_type {
        1 => vec!["receive_time", "transmit_time", "request_src_addr", "request_dest_addr", "sender_client_id"], // ICMP
        2 => vec!["receive_time", "reply_src_port", "reply_dest_port", "code", "transmit_time", "request_src_addr", "request_dest_addr", "sender_client_id", "request_src_port", "request_dest_port"], // UDP/DNS
        3 => vec!["receive_time", "reply_src_port", "reply_dest_port", "seq", "ack"], // TCP
        4 => vec!["receive_time", "reply_src_port", "reply_dest_port", "code", "sender_client_id", "chaos_data"], // UDP/CHAOS
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
/// * 'receiver_client_id' - The client ID of the receiver
///
/// * 'task_type' - The type of task that is being performed
fn get_result(
    result: VerfploeterResult,
    receiver_client_id: u32,
    task_type: u32
) -> Vec<String> {
    match result.value.unwrap() {
        ResultTrace(trace) => {
            let ipresult = trace.ip_result.unwrap();
            let source_mb = ipresult.get_source_address_str();
            let ttl = trace.ttl;
            let receive_time = trace.receive_time.to_string();
            let transmit_time = trace.transmit_time.to_string();
            let sender_client_id = trace.sender_client_id.to_string();

            return match trace.value.unwrap() {
                Value::Ping(ping) => {
                    let inner_ip = ping.ip_result.unwrap();
                    let source = inner_ip.get_source_address_str();
                    let destination = inner_ip.get_dest_address_str();

                    vec![receiver_client_id.to_string(), source, destination, ttl.to_string(), source_mb, sender_client_id, receive_time, transmit_time]
                }
                Value::Udp(udp) => {
                    let inner_ip = udp.ip_result.unwrap();
                    let source = inner_ip.get_source_address_str();
                    let destination = inner_ip.get_dest_address_str();
                    let source_port = udp.source_port.to_string();
                    let destination_port = udp.destination_port.to_string();

                    vec![receiver_client_id.to_string(), source, destination, ttl.to_string(), source_mb, sender_client_id, receive_time, transmit_time, source_port, destination_port]
                }
                Value::Tcp(tcp) => {
                    let inner_ip = tcp.ip_result.unwrap();
                    let source = inner_ip.get_source_address_str();
                    let destination = inner_ip.get_dest_address_str();
                    let source_port = tcp.source_port.to_string();
                    let destination_port = tcp.destination_port.to_string();
                    let seq = tcp.seq.to_string();
                    let ack = tcp.ack.to_string();

                    vec![receiver_client_id.to_string(), source, destination, ttl.to_string(), source_mb, sender_client_id, receive_time, transmit_time, source_port, destination_port, seq, ack]
                }
            }
        }
        ResultPing(ping) => {
            let recv_time = ping.receive_time.to_string();

            let ip_result = ping.ip_result.unwrap();
            let reply_src = ip_result.get_source_address_str();
            let reply_dest = ip_result.get_dest_address_str();
            let ttl = ip_result.ttl.to_string();

            // Ping payload
            let payload = ping.payload.unwrap();
            let transmit_time = payload.transmit_time.to_string();
            let request_src = payload.source_address.unwrap().to_string();
            let request_dest = payload.destination_address.unwrap().to_string();
            let sender_client_id = payload.sender_client_id.to_string();

            return vec![receiver_client_id.to_string(), reply_src, reply_dest, ttl, recv_time, transmit_time, request_src, request_dest, sender_client_id];
        }
        ResultUdp(udp) => {
            let recv_time = udp.receive_time.to_string();
            let reply_source_port = udp.source_port.to_string();
            let reply_destination_port = udp.destination_port.to_string();
            let reply_code = udp.code.to_string();

            let ip_result = udp.ip_result.unwrap();
            let reply_src = ip_result.get_source_address_str();
            let reply_dest = ip_result.get_dest_address_str();
            let ttl = ip_result.ttl.to_string();

            if udp.payload == None { // ICMP reply
                if task_type == 2 {
                    let transmit_time = "-1".to_string();
                    let request_src = "-1".to_string();
                    let request_dest = "-1".to_string();
                    let sender_client_id = "-1".to_string();
                    let request_src_port = "-1".to_string();
                    let request_dest_port = "-1".to_string();

                    return vec![receiver_client_id.to_string(), reply_src, reply_dest, ttl, recv_time, reply_source_port, reply_destination_port, reply_code, transmit_time, request_src, request_dest, sender_client_id, request_src_port, request_dest_port];
                } else if task_type == 4 {
                    let sender_client_id = "-1".to_string();
                    let chaos = "-1".to_string();

                    return vec![receiver_client_id.to_string(), reply_src, reply_dest, ttl, recv_time, reply_source_port, reply_destination_port, reply_code, sender_client_id, chaos];
                } else {
                    panic!("No payload found for unexpected UDP result!");
                }
            }

            let payload = udp.payload.expect("No payload found for UDP result!");

            match payload.value {
                Some(DnsARecord(dns_a_record)) => {
                    let transmit_time = dns_a_record.transmit_time.to_string();
                    // IP::from(payload.source_address.unwrap()).to_string()
                    let request_src = dns_a_record.source_address.unwrap().to_string();
                    let request_dest = dns_a_record.destination_address.unwrap().to_string();
                    let sender_client_id = dns_a_record.sender_client_id.to_string();
                    let request_src_port = dns_a_record.source_port.to_string();
                    let request_dest_port = "53".to_string();

                    return vec![receiver_client_id.to_string(), reply_src, reply_dest, ttl, recv_time, reply_source_port, reply_destination_port, reply_code, transmit_time, request_src, request_dest, sender_client_id, request_src_port, request_dest_port];
                },
                Some(DnsChaos(dns_chaos)) => {
                    let sender_client_id = dns_chaos.sender_client_id.to_string();
                    let chaos = dns_chaos.chaos_data;

                    return vec![receiver_client_id.to_string(), reply_src, reply_dest, ttl, recv_time, reply_source_port, reply_destination_port, reply_code, sender_client_id, chaos];
                },
                None => {
                    panic!("No payload found for UDP result!");
                }
            }
        },
        ResultTcp(tcp) => {
            let recv_time = tcp.receive_time.to_string();

            let ip_result = tcp.ip_result.unwrap();
            let reply_src = ip_result.get_source_address_str();
            let reply_dest = ip_result.get_dest_address_str();
            let ttl = ip_result.ttl.to_string();

            let reply_source_port = tcp.source_port.to_string();
            let reply_destination_port = tcp.destination_port.to_string();

            let seq = tcp.seq.to_string();
            let ack = tcp.ack.to_string();

            return vec![receiver_client_id.to_string(), reply_src, reply_dest, ttl, recv_time, reply_source_port, reply_destination_port, seq, ack];
        }
    }
}

use std::collections::HashMap;
use std::error::Error;
use rand::seq::SliceRandom;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Add;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use chrono::{Datelike, Local, Timelike};
use clap::ArgMatches;
use prettytable::{Attr, Cell, color, format, Row, Table};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tonic::Request;
use tonic::transport::Channel;
use std::process::{Command, Stdio};

use crate::custom_module;
use custom_module::IP;
use custom_module::verfploeter::{
    VerfploeterResult, Client, controller_client::ControllerClient, TaskResult, ScheduleTask,
    schedule_task, Ping, Udp, Tcp, Empty, Address, address::Value::V4, address::Value::V6,
    verfploeter_result::Value::Ping as ResultPing, verfploeter_result::Value::Udp as ResultUdp,
    verfploeter_result::Value::Tcp as ResultTcp
};

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
    let addr = "https://".to_string().add(args.value_of("server").unwrap());
    // Create client connection with the Controller Server
    println!("[CLI] Connecting to Controller Server at address {}", addr);
    let grpc_client = ControllerClient::connect(addr).await?;
    println!("[CLI] Connected to Controller Server");

    let mut cli_client = CliClient {
        grpc_client,
    };

    if args.subcommand_matches("client-list").is_some() {
        // Perform the client-list command
        cli_client.list_clients_to_server().await
    } else if let Some(matches) = args.subcommand_matches("start") {
        // Start a Verfploeter measurement

        // Check if iGreedy is present, and has a valid path if so
        let igreedy: Option<String> = if matches.is_present("LIVE") {
            let path = matches.value_of("LIVE");

            if let Ok(metadata) = std::fs::metadata(path.unwrap()) {
                println!("metadata: {:?}", metadata);

                println!("Path: {}", path.unwrap());

                let output = Command::new("python3")
                    .arg(path.unwrap())
                    .stdout(Stdio::piped()) // Capture stdout
                    .spawn().expect("Failed to spawn iGreedy")
                    .wait_with_output().expect("Failed to execute iGreedy");

                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    println!("Script output:\n{}", stdout);
                } else {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    println!("Script output:\n{}", stdout);
                    println!("The script executed but returned a non-zero exit status: {}", output.status);
                    panic!("iGreedy did not get executed properly.")
                }
            } else {
                panic!("Invalid iGreedy path: {}", path.unwrap());
            }
            Some(path.unwrap().to_owned())
        } else {
            None
        };

        // Source IP for the measurement
        let source_ip = IP::from(matches.value_of("SOURCE_IP").unwrap().to_string());

        // Get the target IP addresses
        let ip_file = matches.value_of("IP_FILE").unwrap();
        let file = File::open("./data/".to_string().add(ip_file)).unwrap_or_else(|_| panic!("Unable to open file {}", "./data/".to_string().add(ip_file)));
        let buf_reader = BufReader::new(file);

        // let first = buf_reader.lines().next().unwrap().unwrap(); // TODO will this cause the first address to be skipped?
        // let v4 = if first.contains(':') { false } else { true };

        // let addresses: Vec<Address> = if v4 {
        //     let mut ips: Vec<_> = buf_reader // TODO create list of Addresses (make sure they are all ipv4 or ipv6)
        //         .lines()
        //         .map(|l| {
        //             let address_str = &l.unwrap();
        //             if v4 {
        //                 match Ipv4Addr::from_str(address_str) {
        //                     Ok(a) => u32::from(a),
        //                     Err(_) => panic!("Unable to parse v4 address: {}", address_str),
        //                 }
        //             } else {
        //                 match Ipv6Addr::from_str(address_str) {
        //                     Ok(a) => u128::from(a),
        //                     Err(_) => panic!("Unable to parse v6 address: {}", address_str),
        //                 }
        //             }
        //         })
        //         .collect::<Vec<_>>();
        // } else {
        //
        // }

        // TODO make sure that all addresses are the same type (v4 or v6)

        let mut ips: Vec<Address> = buf_reader
            .lines()
            .map(|l| {
                let address_str = l.unwrap();
                Address::from(IP::from(address_str))
            })
            .collect::<Vec<_>>();

        debug!("Loaded [{}] IP addresses on _ips vector", ips.len());

        // Shuffle the hitlist if desired
        let shuffle = if matches.is_present("SHUFFLE") {
            let mut rng = rand::thread_rng();
            ips.as_mut_slice().shuffle(&mut rng);
            true
        } else {
            false
        };

        // Get the clients that have to send out probes
        let client_ids = if matches.is_present("CLIENTS") {
            let client_ids = matches.values_of("CLIENTS").unwrap();
            let client_ids: Vec<u32> = client_ids
                .map(|id| u32::from_str(id).expect(&format!("Unable to parse client ID: {}", id)))
                .collect();

            println!("[CLI] Probes will be sent out from these clients: {:?}", client_ids);
            client_ids
        } else {
            println!("[CLI] Probes will be sent out from all clients");
            vec![]
        };

        // Get the type of task
        let task_type = if let Ok(task_type) = u32::from_str(matches.value_of("TYPE").unwrap()) { task_type } else { panic!("Invalid task type! (can be either 1, 2, 3, or 4)") };
        // We only accept task types 1, 2, 3, 4
        if (task_type < 1) | (task_type > 4) {
            panic!("Invalid task type value! (can be either 1, 2, or 3)")
        }
        // Check for command-line option that determines whether to stream to CLI
        let cli = matches.is_present("STREAM");

        // Get the rate for this task
        let rate = if matches.is_present("RATE") {
            u32::from_str(matches.value_of("RATE").unwrap()).unwrap()
        } else {
            1000
        };

        let t_type = match task_type {
            1 => "ICMP/ping",
            2 => "UDP/DNS",
            3 => "TCP/SYN-ACK",
            4 => "UDP/CHAOS",
            _ => "Undefined (defaulting to ICMP/ping)"
        };

        println!("[CLI] Performing {} task targeting {} addresses, from source {}, and a rate of {}", t_type, ips.len(), source_ip.to_string(), rate);
        println!("[CLI] This task will take an estimated {:.2} minutes", ((ips.len() as f32 / rate as f32) + 10.0) / 60.0);

        // Create the task and send it to the server
        let schedule_task = create_schedule_task(source_ip, ips, task_type, rate, client_ids);
        cli_client.do_task_to_server(schedule_task, task_type, cli, shuffle, ip_file, igreedy).await
    } else {
        println!("[CLI] Unrecognized command");
        unimplemented!();
    }
}

/// Create a Verfploeter ScheduleTask message that can be sent to the server.
///
/// # Arguments
///
/// * 'source_address' - the source address to be used for this task (will be overwritten by the clients if they have a source address specified locally)
///
/// * 'destination_addresses' - a vector of destination addresses that will be probed in this task
///
/// * 'task_type' - the type of task, can be 1: ICMP/ping, 2: UDP/A, 3: TCP, 4: UDP/CHAOS
///
/// * 'rate' - the rate (packets / second) at which clients will send out probes (default: 1000)
///
/// * 'client_ids' - the list of clients (by IDs) who participate in the measurement (empty list means all clients participate)
///
/// # Examples
///
/// ```
/// let task = create_schedule_task(124.0.0.0, vec![1.1.1.1, 8.8.8.8], 1, 1400, vec![]);
/// ```
fn create_schedule_task(source_address: IP, destination_addresses: Vec<Address>, task_type: u32, rate: u32, client_ids: Vec<u32>) -> ScheduleTask {
    match task_type {
        1 => { // ICMP
            return ScheduleTask {
                rate,
                clients: client_ids,
                source_address: Some(Address::from(source_address)),
                task_type,
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
    /// * 'task' - the task that is being sent to the server
    ///
    /// * 'task_type' - the type of task that is being sent, and the type of the task results we will receive
    ///
    /// * 'cli' - a boolean that determines whether the results should be printed to the command-line (will be true if --stream was added to the start command)
    ///
    /// * 'shuffle' - a boolean whether the hitlist has been shuffled or not
    ///
    /// * 'live' - if true results will be checked for anycast targets as they come in.
    async fn do_task_to_server(&mut self, task: ScheduleTask, task_type: u32, cli: bool, shuffle: bool, hitlist: &str, igreedy: Option<String>) -> Result<(), Box<dyn Error>> {
        let rate = task.rate;
        let source_address = IP::from(task.clone().source_address.unwrap()).to_string();

        // Obtain connected client information for metadata
        let request = Request::new(Empty::default());
        let response = self.grpc_client.list_clients(request).await?;
        let mut clients = HashMap::new();
        for client in response.into_inner().clients {
            clients.insert(client.client_id, client.metadata.clone().unwrap());
        }

        let request = Request::new(task);
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

        println!("[CLI] Task sent to server, awaiting results\n[CLI] Time of start measurement {}", Local::now().format("%H:%M:%S"));

        let mut results: Vec<TaskResult> = Vec::new();

        let mut graceful = false;
        // Obtain the Stream from the server and read from it
        let mut stream = response?.into_inner();

        let tx = if igreedy != None {
            // Channel for address_feed
            let (tx, rx) = unbounded_channel();
            address_feed(rx,  Duration::from_secs((clients.len() * 2) as u64), igreedy.unwrap());
            Some(tx)
        } else {
            None
        };

        while let Ok(Some(task_result)) = stream.message().await {
            // A default result notifies the CLI that it should not expect any more results
            if task_result == TaskResult::default() {
                graceful = true;
                break;
            }

            println!("Received result from client {:?}", task_result);

            if let Some(tx) = &tx {
                tx.send(task_result.clone()).unwrap();
            }
            results.push(task_result);
        }
        let end = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let length = (end - start) as f64 / 1_000_000_000.0; // Measurement length in seconds
        println!("[CLI] Waited {:.6} seconds for results.", length);

        // If the stream closed during a measurement
        if !graceful { println!("[CLI] Measurement ended prematurely!"); }

        // CSV writer to command-line interface
        let mut wtr_cli = if cli { Some(csv::Writer::from_writer(io::stdout())) } else { None };

        // Get current timestamp and create timestamp file encoding
        let timestamp_end = Local::now();
        let timestamp_end_str = format!("{:04}-{:02}-{:02}T{:02};{:02};{:02}",
                                        timestamp_end.year(), timestamp_end.month(), timestamp_end.day(),
                                        timestamp_end.hour(), timestamp_end.minute(), timestamp_end.second());
        let timestamp_start_str = format!("{:04}-{:02}-{:02}T{:02};{:02};{:02}",
                                        timestamp_start.year(), timestamp_start.month(), timestamp_start.day(),
                                        timestamp_start.hour(), timestamp_start.minute(), timestamp_start.second());

        // Get task type
        let type_str = if task_type == 1 { "ICMP" } else if task_type == 2 { "UDP/DNS" } else if task_type == 3 { "TCP" } else if task_type == 4 { "UDP/CHAOS" } else { "ICMP" };

        // Output file
        let mut file = File::create("./out/output_".to_string().add(type_str).add(&*timestamp_end_str).add(".csv"))?;

        // Write metadata of measurement
        if !graceful {
            file.write_all(b"# Incomplete measurement\n")?;
        } else {
            file.write_all(b"# Completed measurement\n")?;
        }
        file.write_all(format!("# Default source address: {}\n", source_address).as_ref())?;
        if shuffle {
            file.write_all(format!("# Hitlist (shuffled): {}\n", hitlist).as_ref())?;
        } else {
            file.write_all(format!("# Hitlist: {}\n", hitlist).as_ref())?;
        }
        file.write_all(format!("# Task type: {}\n", type_str).as_ref())?;
        // file.write_all(format!("Task ID: {}\n", type_str).as_ref())?; // TODO
        file.write_all(format!("# Probing rate: {}\n", rate).as_ref())?;
        file.write_all(format!("# Start measurement: {}\n", timestamp_start_str).as_ref())?;
        file.write_all(format!("# End measurement: {}\n", timestamp_end_str).as_ref())?;
        file.write_all(format!("# Measurement length (seconds): {:.6}\n", length).as_ref())?;

        file.write_all(b"# Connected clients:\n")?;
        for (id, metadata) in &clients {

            let source_addr = match &metadata.source_address {
                Some(Address { value: Some(V4(v4)) }) => {
                    std::net::Ipv4Addr::from(*v4).to_string()
                },
                Some(Address { value: Some(V6(v6)) }) => {
                    Ipv6Addr::from((v6.p1 as u128) << 64 | v6.p2 as u128).to_string()
                },
                Some(Address { value: None }) => "Default".to_string(),
                None => "Default".to_string(),
            };

            file.write_all(format!("# \t * ID: {}, hostname: {}, source IP: {}\n", id, metadata.hostname, source_addr).as_ref())?;
        }

        file.write_all(b"# ----------\n")?; // Separator metadata, and data
        file.flush()?;

        // Open file again in append mode
        let file = OpenOptions::new()
            .write(true)
            .append(true)
            .open("./out/output_".to_string().add(type_str).add(&*timestamp_end_str).add(".csv"))
            .unwrap();
        // CSV writer for output file
        let mut wtr_file = csv::Writer::from_writer(file);

        // Information contained in TaskResult
        let rows = ["recv_client_id"];
        // Information contained in IPv4 header
        let ipv4_rows = ["reply_src_addr", "reply_dest_addr", "ttl"];
        if task_type == 1 { // ICMP
            let icmp_rows = ["receive_time", "transmit_time", "request_src_addr", "request_dest_addr", "sender_client_id"];

            let mut all_rows = [""; 9];
            all_rows[..1].copy_from_slice(&rows);
            all_rows[1..4].copy_from_slice(&ipv4_rows);
            all_rows[4..].copy_from_slice(&icmp_rows);

            if cli { wtr_cli.as_mut().unwrap().write_record(all_rows)? };
            wtr_file.write_record(all_rows)?;
        } else if task_type == 2 { // UDP/DNS
            let udp_rows = ["receive_time", "reply_src_port", "reply_dest_port", "code",
            "transmit_time", "request_src_addr", "request_dest_addr", "sender_client_id", "request_src_port", "request_dest_port"];

            let mut all_rows = [""; 14];
            all_rows[..1].copy_from_slice(&rows);
            all_rows[1..4].copy_from_slice(&ipv4_rows);
            all_rows[4..].copy_from_slice(&udp_rows);

            if cli { wtr_cli.as_mut().unwrap().write_record(all_rows)? };
            wtr_file.write_record(all_rows)?;
        } else if task_type == 3 { // TCP
            let tcp_rows = ["receive_time", "reply_src_port", "reply_dest_port", "seq", "ack"];

            let mut all_rows = [""; 9];
            all_rows[..1].copy_from_slice(&rows);
            all_rows[1..4].copy_from_slice(&ipv4_rows);
            all_rows[4..].copy_from_slice(&tcp_rows);

            if cli { wtr_cli.as_mut().unwrap().write_record(all_rows)? };
            wtr_file.write_record(all_rows)?;
        } else if task_type == 4 { // UDP/CHAOS
            println!("UDP/CHAOS not implemented yet!");
            // TODO
        }

        // Loop over the results and write them to CLI/file
        for result in results {
            println!("Result : {:?}", result);
            let client: Client = result.client.unwrap();
            let receiver_client_id = client.client_id.to_string();
            let verfploeter_results: Vec<VerfploeterResult> = result.result_list;

            // TaskResult information TODO TaskResult still contains hostname and task_id which does not need to be repeated
            let record: [&str; 1] = [&receiver_client_id];

            for verfploeter_result in verfploeter_results {
                let value = verfploeter_result.value.unwrap();
                match value {
                    ResultPing(ping) => {
                        let recv_time = ping.receive_time.to_string();

                        let ip_result = ping.ip_result.unwrap();
                        let reply_src = ip_result.get_source_address_str();
                        let reply_dest = ip_result.get_dest_address_str();
                        let ttl = ip_result.ttl.to_string();

                        // Ping payload
                        let payload = ping.payload.unwrap();
                        let transmit_time = payload.transmit_time.to_string();
                        let request_src = IP::from(payload.source_address.unwrap()).to_string();
                        let request_dest = IP::from(payload.destination_address.unwrap()).to_string();
                        let sender_client_id = payload.sender_client_id.to_string();

                        let record_ping: [&str; 8] = [&reply_src, &reply_dest, &ttl, &recv_time, &transmit_time, &request_src, &request_dest, &sender_client_id];
                        let mut all_records = [""; 9];
                        all_records[..1].copy_from_slice(&record);
                        all_records[1..].copy_from_slice(&record_ping);


                        if cli { wtr_cli.as_mut().unwrap().write_record(all_records)? };
                        wtr_file.write_record(all_records)?;
                    }
                    ResultUdp(udp) => {
                        println!("UDP result: {:?}", udp);
                        let recv_time = udp.receive_time.to_string();
                        let reply_source_port = udp.source_port.to_string();
                        let reply_destination_port = udp.destination_port.to_string();
                        let reply_code = udp.code.to_string();

                        let ip_result = udp.ip_result.unwrap();
                        let reply_src = ip_result.get_source_address_str();
                        let reply_dest = ip_result.get_dest_address_str();
                        let ttl = ip_result.ttl.to_string();


                        let payload = udp.payload.unwrap();
                        let transmit_time = payload.transmit_time.to_string();
                        let request_src = Ipv4Addr::from(payload.source_address).to_string();
                        let request_dest = Ipv4Addr::from(payload.destination_address).to_string();
                        let sender_client_id = payload.sender_client_id.to_string();
                        let request_src_port = payload.source_port.to_string();

                        let record_udp: [&str; 13] = [&reply_src, &reply_dest, &ttl, &recv_time, &reply_source_port, &reply_destination_port, &reply_code, &transmit_time, &request_src, &request_dest, &sender_client_id, &request_src_port, "53"];
                        let mut all_records = [""; 14];
                        all_records[..1].copy_from_slice(&record);
                        all_records[1..].copy_from_slice(&record_udp);

                        if cli { wtr_cli.as_mut().unwrap().write_record(&all_records)? };
                        wtr_file.write_record(&all_records)?;
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

                        let record_tcp: [&str; 8] = [&reply_src, &reply_dest, &ttl, &recv_time, &reply_source_port, &reply_destination_port, &seq, &ack];
                        let mut all_records = [""; 9];
                        all_records[..1].copy_from_slice(&record);
                        all_records[1..].copy_from_slice(&record_tcp);

                        if cli { wtr_cli.as_mut().unwrap().write_record(all_records)? };
                        wtr_file.write_record(all_records)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Sends a list clients command to the server, awaits the result, and prints it to command-line.
    async fn list_clients_to_server(&mut self) -> Result<(), Box<dyn Error>> {
        println!("[CLI] Sending list clients to server");
        let request = Request::new(Empty::default());
        let response = self.grpc_client.list_clients(request).await?;

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
        ]));
        for client in response.into_inner().clients {

            let metadata = client.metadata.clone().unwrap();

            let sa = match &metadata.source_address {
                Some(Address { value: Some(V4(v4)) }) => {
                    std::net::Ipv4Addr::from(*v4).to_string()
                },
                Some(Address { value: Some(V6(v6)) }) => {
                    Ipv6Addr::from((v6.p1 as u128) << 64 | v6.p2 as u128).to_string()
                },
                Some(Address { value: None }) => "Default".to_string(),
                None => "Default".to_string(),
            };

            table.add_row(prettytable::row!(
                    metadata.hostname,
                    client.client_id,
                    sa,
                ));
        }
        table.printstd();

        Ok(())
    }
}

/// Check for Anycast addresses live, by keeping track of the number of unique clients receiving a response for all addresses.
///
/// # Arguments
///
/// * 'rx' - Receives task results to be analyzed
///
/// * 'cleanup_interval' - The interval at which results are cleaned up
///
fn address_feed(mut rx: UnboundedReceiver<TaskResult>, cleanup_interval: Duration, path: String) {
    let map: Arc<Mutex<HashMap<u32, (u8, Instant)>>> = Arc::new(Mutex::new(HashMap::new())); // {Address: (client_ID, timestamp)}

    let map_clone = map.clone();
    // Start the cleanup task in a separate Tokio task
    tokio::spawn(async move {
        loop {
            // Sleep for the cleanup interval
            tokio::time::sleep(cleanup_interval).await;

            // Perform the cleanup
            let mut map = map_clone.lock().unwrap();
            let current_time = Instant::now();

            map.retain(|_, &mut (_, timestamp)| {
                current_time.duration_since(timestamp) <= cleanup_interval
            });
        }
    });

    tokio::spawn(async move {
        // Receive tasks from the outbound channel
        while let Some(task_result) = rx.recv().await {
            // Get the client ID
            let client_id: u8 = task_result.client.unwrap().client_id.try_into().unwrap();

            // Loop over all results
            for result in task_result.result_list {
                // Get the source address of this result
                let address: u32 = match result.value.unwrap() {
                    ResultPing(ping_result) => u32::from_str(&ping_result.ip_result.unwrap().get_source_address_str()).expect("Unable to parse address"),
                    ResultUdp(udp_result) => u32::from_str(&udp_result.ip_result.unwrap().get_source_address_str()).expect("Unable to parse address"),
                    ResultTcp(tcp_result) => u32::from_str(&tcp_result.ip_result.unwrap().get_source_address_str()).expect("Unable to parse address"),
                };

                let mut map = map.lock().unwrap();

                if !map.contains_key(&address) {
                    // If we have not yet recorded this address, make a new entry with current timestamp and the receiving client's ID
                    map.insert(address, (client_id, Instant::now()));
                } else {
                    // If we have already recorded it retrieve the record
                    let (client_id_old, timestamp) = map.get(&address).unwrap().clone();
                    if (client_id_old == 0) | (client_id == client_id_old) {
                        // If the client ID == 0 (already recorded as anycast suspect) or has the same client ID (still unicast suspect) do nothing
                        continue;
                    } else {
                        // If this was also recorded at a different client, it is an anycast suspect
                        // TODO currently spams the CLI
                        println!("[CLI] Anycast suspect! {}", Ipv4Addr::from(address).to_string());
                        igreedy(path.clone(), &Ipv4Addr::from(address).to_string());

                        // TODO keep list of checked anycast targets, and make sure to not check targets multiple times
                        // Set client ID to 0 (already checked)
                        map.insert(address, (0, timestamp));
                    }
                }
            }
        }
    });
}

/// Perform an iGreedy measurement on a given IP address
fn igreedy(path: String, target: &str) {
    let output = format!("igreedy/{}/{}", Local::now().format("%Y%m%d").to_string(), target);

    Command::new("python3")
        .arg(&path)
        .arg("-m")
        .arg(target)
        .arg("-o")
        .arg(&output)
        .spawn().expect("iGreedy failed!");
}

use std::error::Error;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::ops::Add;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use chrono::{Datelike, Timelike};
use clap::ArgMatches;
use prettytable::{Attr, Cell, color, format, Row, Table};
use tonic::Request;
use tonic::transport::Channel;
pub mod verfploeter { tonic::include_proto!("verfploeter"); }
use verfploeter::{ controller_client::ControllerClient, TaskResult };
use crate::cli::verfploeter::verfploeter_result::Value::Ping as ResultPing;
use crate::cli::verfploeter::verfploeter_result::Value::Udp as ResultUdp;
use crate::cli::verfploeter::verfploeter_result::Value::Tcp as ResultTcp;

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
        // Source IP for the measurement
        let source_ip = u32::from(match Ipv4Addr::from_str(matches.value_of("SOURCE_IP").unwrap()) {
            Ok(s) => {s}
            Err(_) => { panic!("Invalid source IP value") }
        });

        // Get the target IP addresses
        let ip_file = matches.value_of("IP_FILE").unwrap();
        let file = File::open("./data/".to_string().add(ip_file)).unwrap_or_else(|_| panic!("Unable to open file {}", "./data/".to_string().add(ip_file)));
        let buf_reader = BufReader::new(file);
        let ips = buf_reader
            .lines()
            .map(|l| {
                let address = u32::from(Ipv4Addr::from_str(&l.unwrap()).unwrap());
                address
            })
            .collect::<Vec<u32>>();
        debug!("Loaded [{}] IP addresses on _ips vector", ips.len());

        // Get the type of task
        let task_type = if let Ok(task_type) = u32::from_str(matches.value_of("TYPE").unwrap()) { task_type } else { panic!("Invalid task type! (can be either 1, 2, or 3)") };
        // We only accept task types 1, 2, 3
        if (task_type < 1) | (task_type > 3) {
            panic!("Invalid task type value! (can be either 1, 2, or 3)")
        }
        // Check for command-line option that determines whether to stream to CLI
        let cli = matches.is_present("STREAM");

        // Create the task and send it to the server
        let schedule_task = create_schedule_task(source_ip, ips, task_type);
        cli_client.do_task_to_server(schedule_task, task_type, cli).await
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
/// * 'task_type' - the type of task, can be 1: ICMP/ping, 2: TCP, 3: UDP
///
/// # Examples
///
/// ```
/// let task = create_schedule_task(124.0.0.0, vec![1.1.1.1, 8.8.8.8], 1);
/// ```
fn create_schedule_task(source_address: u32, destination_addresses: Vec<u32>, task_type: u32) -> verfploeter::ScheduleTask {
    match task_type {
        1 => { // ICMP
            return verfploeter::ScheduleTask {
                data: Some(verfploeter::schedule_task::Data::Ping(verfploeter::Ping {
                    destination_addresses,
                    source_address,
                }))
            }
        }
        2 => { // UDP
            return verfploeter::ScheduleTask {
                data: Some(verfploeter::schedule_task::Data::Udp(verfploeter::Udp {
                    destination_addresses,
                    source_address,
                }))
            }
        }
        3 => { // TCP
            return verfploeter::ScheduleTask {
                data: Some(verfploeter::schedule_task::Data::Tcp(verfploeter::Tcp {
                    destination_addresses,
                    source_address
                }))
            }
        }
        _ => println!("Undefined type, defaulting to ICMP.")
    }

    verfploeter::ScheduleTask {
        data: Some(verfploeter::schedule_task::Data::Ping(verfploeter::Ping {
            destination_addresses,
            source_address,
        }))
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
    async fn do_task_to_server(&mut self, task: verfploeter::ScheduleTask, task_type: u32, cli: bool) -> Result<(), Box<dyn Error>> {
        let request = Request::new(task);
        println!("[CLI] Sending do_task to server");
        let response = self.grpc_client.do_task(request).await?;
        let start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        println!("[CLI] Task sent to server, awaiting results");

        let mut results: Vec<verfploeter::TaskResult> = Vec::new();

        // Obtain the Stream from the server and read from it
        let mut stream = response.into_inner();
        while let Some(task_result) = stream.message().await? {
            // A default result notifies the CLI that it should not expect any more results
            if task_result == TaskResult::default() {
                println!("[CLI] Received task is finished from server");
                let end = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64;
                println!("[CLI] Waited {:.6} seconds for results.", (end - start) as f64 / 1_000_000_000.0);
                break;
            }
            results.push(task_result);
        }

        // CSV writer to command-line interface
        let mut wtr_cli = if cli { Some(csv::Writer::from_writer(io::stdout())) } else { None };

        // Get current timestamp and create timestamp file encoding
        let timestamp = chrono::offset::Local::now();
        let timestamp_str = format!("{:04}-{:02}-{:02}T{:02};{:02};{:02}",
                                timestamp.year(), timestamp.month(), timestamp.day(),
                                timestamp.hour(), timestamp.minute(), timestamp.second());

        // Get task type
        let type_str = if task_type == 1 { "ICMP" } else if task_type == 2 { "UDP" } else if task_type == 3 { "TCP" } else { "ICMP" };

        // CSV writer to file
        let mut wtr_file = csv::Writer::from_path("./out/output_".to_string().add(type_str).add(&*timestamp_str).add(".csv"))?;

        // Information contained in TaskResult
        let rows = ["task_id", "recv_client_id", "hostname"];
        // Information contained in IPv4 header
        let ipv4_rows = ["reply_src_addr", "reply_dest_addr", "ttl"];
        if task_type == 1 { // ICMP
            let icmp_rows = ["receive_time", "transmit_time", "request_src_addr", "request_dest_addr", "sender_client_id"];

            let mut all_rows = [""; 11];
            all_rows[..3].copy_from_slice(&rows);
            all_rows[3..6].copy_from_slice(&ipv4_rows);
            all_rows[6..].copy_from_slice(&icmp_rows);

            if cli { wtr_cli.as_mut().unwrap().write_record(all_rows)? };
            wtr_file.write_record(all_rows)?;
        } else if task_type == 2 { // UDP
            let udp_rows = ["receive_time", "reply_src_port", "reply_dest_port",
            "transmit_time", "request_src_addr", "request_dest_addr", "sender_client_id", "request_src_port", "request_dest_port"];

            let mut all_rows = [""; 15];
            all_rows[..3].copy_from_slice(&rows);
            all_rows[3..6].copy_from_slice(&ipv4_rows);
            all_rows[6..].copy_from_slice(&udp_rows);

            if cli { wtr_cli.as_mut().unwrap().write_record(all_rows)? };
            wtr_file.write_record(all_rows)?;
        } else if task_type == 3 { // TCP
            let tcp_rows = ["receive_time", "reply_src_port", "reply_dest_port", "seq", "ack"];

            let mut all_rows = [""; 11];
            all_rows[..3].copy_from_slice(&rows);
            all_rows[3..6].copy_from_slice(&ipv4_rows);
            all_rows[6..].copy_from_slice(&tcp_rows);

            if cli { wtr_cli.as_mut().unwrap().write_record(all_rows)? };
            wtr_file.write_record(all_rows)?;
        }

        // Loop over the results and write them to CLI/file
        for result in results {
            let task_id = result.task_id.to_string();
            let client: verfploeter::Client = result.client.unwrap();
            let client_id = client.client_id.to_string();
            let hostname: String = client.metadata.unwrap().hostname;
            let verfploeter_results: Vec<verfploeter::VerfploeterResult> = result.result_list;

            // TaskResult information
            let record: [&str; 3] = [&task_id, &client_id, &hostname];

            for verfploeter_result in verfploeter_results {
                let value = verfploeter_result.value.unwrap();
                match value {
                    ResultPing(ping) => {
                        let recv_time = ping.receive_time.to_string();

                        let ipv4result = ping.ipv4_result.unwrap();
                        let reply_src = Ipv4Addr::from(ipv4result.source_address).to_string();
                        let reply_dest = Ipv4Addr::from(ipv4result.destination_address).to_string();
                        let ttl = ipv4result.ttl.to_string();

                        // Ping payload
                        let payload = ping.payload.unwrap();
                        let transmit_time = payload.transmit_time.to_string();
                        let request_src = Ipv4Addr::from(payload.source_address).to_string();
                        let request_dest = Ipv4Addr::from(payload.destination_address).to_string();
                        let sender_client_id = payload.sender_client_id.to_string();

                        let record_ping: [&str; 8] = [&reply_src, &reply_dest, &ttl, &recv_time, &transmit_time, &request_src, &request_dest, &sender_client_id];
                        let mut all_records = [""; 11];
                        all_records[..3].copy_from_slice(&record);
                        all_records[3..].copy_from_slice(&record_ping);


                        if cli { wtr_cli.as_mut().unwrap().write_record(all_records)? };
                        wtr_file.write_record(all_records)?;
                    }
                    ResultUdp(udp) => {
                        let recv_time = udp.receive_time.to_string();
                        let reply_source_port = udp.source_port.to_string();
                        let reply_destination_port = udp.destination_port.to_string();

                        let ipv4result = udp.ipv4_result.unwrap();
                        let reply_src = Ipv4Addr::from(ipv4result.source_address).to_string();
                        let reply_dest = Ipv4Addr::from(ipv4result.destination_address).to_string();
                        let ttl = ipv4result.ttl.to_string();


                        let payload = udp.payload.unwrap();
                        let transmit_time = payload.transmit_time.to_string();
                        let request_src = Ipv4Addr::from(payload.source_address).to_string();
                        let request_dest = Ipv4Addr::from(payload.destination_address).to_string();
                        let sender_client_id = payload.sender_client_id.to_string();
                        let request_src_port = payload.source_port.to_string();

                        let record_udp: [&str; 12] = [&recv_time, &reply_source_port, &reply_destination_port, &reply_src, &reply_dest, &ttl, &transmit_time, &request_src, &request_dest, &sender_client_id, &request_src_port, "53"];
                        let mut all_records = [""; 15];
                        all_records[..3].copy_from_slice(&record);
                        all_records[3..].copy_from_slice(&record_udp);

                        if cli { wtr_cli.as_mut().unwrap().write_record(&all_records)? };
                        wtr_file.write_record(&all_records)?;
                    },
                    ResultTcp(tcp) => {
                        let recv_time = tcp.receive_time.to_string();

                        let ipv4result = tcp.ipv4_result.unwrap();
                        let reply_src = Ipv4Addr::from(ipv4result.source_address).to_string();
                        let reply_dest = Ipv4Addr::from(ipv4result.destination_address).to_string();
                        let ttl = ipv4result.ttl.to_string();

                        let reply_source_port = tcp.source_port.to_string();
                        let reply_destination_port = tcp.destination_port.to_string();

                        let seq = tcp.seq.to_string();
                        let ack = tcp.ack.to_string();

                        let record_tcp: [&str; 8] = [&reply_src, &reply_dest, &ttl, &recv_time, &reply_source_port, &reply_destination_port, &seq, &ack];
                        let mut all_records = [""; 11];
                        all_records[..3].copy_from_slice(&record);
                        all_records[3..].copy_from_slice(&record_tcp);

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
        let request = Request::new(verfploeter::Empty::default());
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
        ]));
        for client in response.into_inner().clients {
            table.add_row(prettytable::row!(
                    client.metadata.clone().unwrap().hostname,
                    client.client_id,
                ));
        }
        table.printstd();

        Ok(())
    }
}

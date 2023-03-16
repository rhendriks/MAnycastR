use std::error::Error;
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::net::Ipv4Addr;
use std::ops::Add;
use std::str::FromStr;

use chrono::{Datelike, Timelike};
use clap::ArgMatches;
use prettytable::{Attr, Cell, color, format, Row, Table};
use tonic::Request;
use tonic::transport::Channel;

// Load in struct definitions for the message types
use verfploeter::{
    controller_client::ControllerClient, TaskResult, ScheduleTask
};

use crate::cli::verfploeter::verfploeter_result::Value::Ping as ResultPing;
use crate::cli::verfploeter::verfploeter_result::Value::Udp as ResultUdp;
use crate::cli::verfploeter::verfploeter_result::Value::Tcp as ResultTcp;

// Load in the generated code from verfploeter.proto using tonic
pub mod verfploeter {
    tonic::include_proto!("verfploeter");
}

pub struct CliClass {
    grpc_client: ControllerClient<Channel>,
}

// Execute the command that is passed in the command-line
#[tokio::main]
pub async fn execute(args: &ArgMatches) -> Result<(), Box<dyn Error>> {
    let addr = "https://".to_string().add(args.value_of("server").unwrap());
    // Create client connection with the Controller Server
    println!("[CLI] Connecting to Controller Server at address {}", addr);
    let client = ControllerClient::connect(addr).await?;
    println!("[CLI] Connected to Controller Server");

    let mut cli_class = CliClass {
        grpc_client: client,
    };

    // If the client-list command was specified
    if args.subcommand_matches("client-list").is_some() {
        cli_class.list_clients_to_server(verfploeter::Empty::default()).await
        // If the start command was specified
    } else if let Some(matches) = args.subcommand_matches("start") {

        // Source IP for the measurement
        let source_ip: u32 =
            u32::from(Ipv4Addr::from_str(matches.value_of("SOURCE_IP").unwrap()).unwrap());

        // Get the specified IP file
        let ip_file = matches.value_of("IP_FILE").unwrap();

        // Get the destination addresses
        let file = File::open("./data/".to_string().add(ip_file)).unwrap_or_else(|_| panic!("Unable to open file {}", "./data/".to_string().add(ip_file)));
        let buf_reader = BufReader::new(file);
        let ips = buf_reader
            .lines()
            .map(|l| {
                let address = u32::from(Ipv4Addr::from_str(&l.unwrap()).unwrap());
                address
            })
            .collect::<Vec<u32>>();
        debug!("Loaded [{}] IPAddresses on _ips vector",ips.len());

        // Get the type of task
        let task_type = if let Ok(task_type) = u32::from_str(matches.value_of("TYPE").unwrap()) { task_type} else { todo!() };

        let schedule_task = create_schedule_task(source_ip, ips, task_type);

        cli_class.do_task_to_server(schedule_task, task_type).await
    } else {
        unimplemented!();
    }
}

// Create a verfploeter::ScheduleTask that can be sent to the server
pub fn create_schedule_task(source_address: u32, destination_addresses: Vec<u32>, task_type: u32) -> verfploeter::ScheduleTask {
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
        _ => (println!("Undefined type!")) // TODO handle this properly
    }


    verfploeter::ScheduleTask {
        data: Some(verfploeter::schedule_task::Data::Ping(verfploeter::Ping {
            destination_addresses,
            source_address,
        }))
    }
}

impl CliClass {
    // rpc do_task(ScheduleTask) returns (Ack) {}
    async fn do_task_to_server(&mut self, schedule_task: verfploeter::ScheduleTask, task_type: u32) -> Result<(), Box<dyn Error>> {
        let request = Request::new(schedule_task);
        println!("[CLI] Sending do_task to server");
        let response = self.grpc_client.do_task(request).await?;

        let mut results: Vec<verfploeter::TaskResult> = Vec::new();

        // Obtain the Stream from the server and read from it
        let mut stream = response.into_inner();
        while let Some(task_result) = stream.message().await? {
            // A default result notifies the CLI that it should not expect any more results
            if task_result == TaskResult::default() {
                break;
            }

            // println!("[CLI] Received task result! {:?}", task_result);
            println!("[CLI] Received task result");
            println!("Result: {:?}", task_result);
            results.push(task_result);
        }

        // CSV writer to command-line interface
        let mut wtr_cli = csv::Writer::from_writer(io::stdout());

        // Get current timestamp
        let timestamp = chrono::offset::Local::now();

        let timestamp_str = timestamp.year().to_string()
            .add("-").add(&*timestamp.month().to_string())
            .add("-").add(&*timestamp.day().to_string())
            .add("T").add(&*timestamp.hour().to_string())
            .add(",").add(&*timestamp.minute().to_string())
            .add(",").add(&*timestamp.second().to_string());

        // CSV writer to file
        let mut wtr_file = csv::Writer::from_path("./out/output".to_string().add(&*timestamp_str).add(".csv"))?;

        let rows = ["task_id", "recv_client_id", "hostname"];
        let ipv4_rows = ["reply_src_addr", "reply_dest_addr", "ttl"];
        // TODO based on task type this will be different
        if task_type == 1 { // ICMP
            let icmp_rows = ["receive_time", "transmit_time", "request_src_addr", "request_dest_addr", "sender_client_id"];

            let mut all_rows = [""; 12];
            all_rows[..3].copy_from_slice(&rows);
            all_rows[3..6].copy_from_slice(&ipv4_rows);
            all_rows[6..].copy_from_slice(&icmp_rows);

            wtr_cli.write_record(all_rows)?;
            wtr_file.write_record(all_rows)?;
        } else if task_type == 2 { // UDP
            let udp_rows = ["receive_time", "reply_src_port", "reply_dest_port",
            "transmit_time", "request_src_addr", "request_dest_addr", "sender_client_id", "request_src_port", "request_dest_port"];

            let mut all_rows = [""; 15];
            all_rows[..3].copy_from_slice(&rows);
            all_rows[3..6].copy_from_slice(&ipv4_rows);
            all_rows[6..].copy_from_slice(&udp_rows);

            wtr_cli.write_record(all_rows)?;
            wtr_file.write_record(all_rows)?;
        } else if task_type == 3 { // TCP
            let tcp_rows = ["receive_time", "reply_src_port", "reply_dest_port", "seq", "ack"];

            let mut all_rows = [""; 10];
            all_rows[..3].copy_from_slice(&rows);
            all_rows[3..6].copy_from_slice(&ipv4_rows);
            all_rows[6..].copy_from_slice(&tcp_rows);

            wtr_cli.write_record(all_rows)?;
            wtr_file.write_record(all_rows)?;
        }

        // Loop over the results and write them to CLI/file
        for result in results {
            let task_id = result.task_id.to_string();
            let client: verfploeter::Client = result.client.unwrap();
            let client_id = client.client_id.to_string();
            let hostname: String = client.metadata.unwrap().hostname;
            let verfploeter_results: Vec<verfploeter::VerfploeterResult> = result.result_list;

            let record: [&str; 3] = [&task_id, &client_id, &hostname];

            for verfploeter_result in verfploeter_results {
                // let Some(ping)
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

                        let record_ping: [&str; 8] = [&recv_time, &reply_src, &reply_dest, &ttl, &transmit_time, &request_src, &request_dest, &sender_client_id];
                        let mut all_records = [""; 11];
                        all_records[..3].copy_from_slice(&record);
                        all_records[3..11].copy_from_slice(&record_ping);


                        wtr_cli.write_record(all_records)?;
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
                        let request_dest_port = payload.destination_port.to_string();

                        let record_udp: [&str; 12] = [&recv_time, &reply_source_port, &reply_destination_port, &reply_src, &reply_dest, &ttl, &transmit_time, &request_src, &request_dest, &sender_client_id, &request_src_port, &request_dest_port];
                        let mut all_records = [""; 15];
                        all_records[..3].copy_from_slice(&record);
                        all_records[3..14].copy_from_slice(&record_udp);

                        wtr_cli.write_record(&all_records)?;
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

                        let record_tcp: [&str; 8] = [&recv_time, &reply_src, &reply_dest, &ttl, &reply_source_port, &reply_destination_port, &seq, &ack];
                        let mut all_records = [""; 11];
                        all_records[..3].copy_from_slice(&record);
                        all_records[3..12].copy_from_slice(&record_tcp);

                        wtr_cli.write_record(all_records)?;
                        wtr_file.write_record(all_records)?;
                    }
                }
            }
        }

        Ok(())
    }

    // rpc list_clients(Empty) returns (ClientList) {}
    async fn list_clients_to_server(&mut self, empty: verfploeter::Empty) -> Result<(), Box<dyn Error>> {
        println!("[CLI] Sending list clients to server");
        let request = Request::new(empty);
        let response = self.grpc_client.list_clients(request).await?;

        let mut table = Table::new();
        table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
        table.add_row(Row::new(vec![
            Cell::new("Hostname")
                .with_style(Attr::Bold)
                .with_style(Attr::ForegroundColor(color::GREEN)),
            Cell::new("Version")
                .with_style(Attr::Bold)
                .with_style(Attr::ForegroundColor(color::GREEN)),
        ]));
        for client in response.into_inner().clients {
            table.add_row(prettytable::row!(
                    client.metadata.clone().unwrap().hostname,
                    // client.metadata.clone().unwrap().version,
                ));
        }
        table.printstd();

        Ok(())
    }
}

use tonic::Request;
use prettytable::{color, format, Attr, Cell, Row, Table};
use tonic::transport::Channel;
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
use crate::cli::verfploeter::verfploeter_result::Value::Ping as ResultPing;

// Load in the generated code from verfploeter.proto using tonic
pub mod verfploeter {
    tonic::include_proto!("verfploeter");
}

// Load in struct definitions for the message types
use verfploeter::{
    TaskResult, controller_client::ControllerClient,
};

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

        let schedule_task = create_schedule_task(source_ip, ips);

        cli_class.do_task_to_server(schedule_task).await

    } else {
        unimplemented!();
    }
}

// Create a verfploeter::ScheduleTask that can be sent to the server
pub fn create_schedule_task(source_address: u32, destination_addresses: Vec<u32>) -> verfploeter::ScheduleTask {
    verfploeter::ScheduleTask {
        data: Some(verfploeter::schedule_task::Data::Ping(verfploeter::Ping {
            destination_addresses,
            source_address,
        }))
    }
}

impl CliClass {

    // rpc do_task(ScheduleTask) returns (Ack) {}
    async fn do_task_to_server(&mut self, schedule_task: verfploeter::ScheduleTask) -> Result<(), Box<dyn Error>> {
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

        wtr_cli.write_record(&["recv_hostname", "reply_src", "reply_dest", "request_src", "request_dest", "recv_time", "send_time", "TTL", "recv_client_id", "sender_client_id"])?;
        wtr_file.write_record(&["recv_hostname", "reply_src", "reply_dest", "request_src", "request_dest", "recv_time", "send_time", "TTL", "recv_client_id", "sender_client_id"])?;

        // Loop over the results and write them to CLI/file
        for result in results {
            let _: u32 = result.task_id;
            let client: verfploeter::Client = result.client.unwrap();
            let hostname: String = client.metadata.unwrap().hostname;
            let verfploeter_results: Vec<verfploeter::VerfploeterResult> = result.result_list;

            for verfploeter_result in verfploeter_results {
                // let Some(ping)
                let value = verfploeter_result.value.unwrap();
                match value {
                    ResultPing(ping) => {
                        let reply_src = Ipv4Addr::from(ping.source_address).to_string();
                        let reply_dest = Ipv4Addr::from(ping.destination_address).to_string();
                        let recv_time = ping.receive_time.to_string();
                        let recv_client_id = ping.receiver_client_id.to_string();

                        let payload = ping.payload.unwrap();
                        let transmit_time = payload.transmit_time.to_string();
                        let sender_client_id = payload.sender_client_id.to_string();
                        let request_src = Ipv4Addr::from(payload.source_address).to_string();
                        let request_dest = Ipv4Addr::from(payload.destination_address).to_string();


                        let ttl = ping.ttl.to_string();
                        wtr_cli.write_record(&[hostname.clone(), reply_src.clone(), reply_dest.clone(), request_src.clone(), request_dest.clone(), recv_time.clone(), transmit_time.clone(), ttl.clone(), recv_client_id.clone(), sender_client_id.clone()])?;
                        wtr_file.write_record(&[hostname.clone(), reply_src, reply_dest, request_src, request_dest, recv_time, transmit_time, ttl, recv_client_id, sender_client_id])?;
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
                    client.metadata.clone().unwrap().version,
                ));
        }
        table.printstd();

        Ok(())
    }
}

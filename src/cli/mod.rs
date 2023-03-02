// gRPC/tonic dependencies
use futures_core::Stream;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;

// Load in the generated code from verfploeter.proto using tonic
pub mod verfploeter {
    tonic::include_proto!("verfploeter"); // Based on the 'verfploeter' package name
}

// Load in struct definitions for the message types
use verfploeter::{
    Empty, Ack, TaskId, ScheduleTask, ClientList, Client, Task, Metadata, Ping, TaskResult,
    VerfploeterResult, PingResult, PingPayload,
};

// Load in the ControllerClient
use verfploeter::controller_client::ControllerClient;
// Load in struct definitions for the message types

use tonic::transport::Channel;
use std::error::Error;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::net::Ipv4Addr;
use std::ops::Add;
use std::str::FromStr;
use clap::ArgMatches;

pub struct CliClass {
    grpc_client: ControllerClient<Channel>,
}

// Execute the command as part of the argument
#[tokio::main]
pub async fn execute(args: &ArgMatches) -> Result<(), Box<dyn Error>> {

    // Create client connection with the Controller Server
    println!("[CLI] Connecting to Controller Server from CLI...");
    let mut client = ControllerClient::connect("http://[::1]:10001").await?;
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
                let mut address = u32::from(Ipv4Addr::from_str(&l.unwrap()).unwrap());
                address
            })
            .collect::<Vec<u32>>();
        debug!("Loaded [{}] IPAddresses on _ips vector",ips.len());

        let schedule_task = createScheduleTask(source_ip, ips);

        cli_class.do_task_to_server(schedule_task).await

    } else {
        unimplemented!();
    }
}

// Create a verfploeter::ScheduleTask that can be sent to the server
pub fn createScheduleTask(source_address: u32, destination_addresses: Vec<u32>) -> verfploeter::ScheduleTask {
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
        println!("[CLI] Sending schedule task to server {:?}", request);
        let response = self.grpc_client.do_task(request).await?;

        let mut stream = response.into_inner();

        while let Some(task_result) = stream.message().await? {
            println!("[CLI] Received task result! {:?}", task_result);
        }

        Ok(())
    }

    // rpc list_clients(Empty) returns (ClientList) {}
    async fn list_clients_to_server(&mut self, empty: verfploeter::Empty) -> Result<(), Box<dyn Error>> {
        println!("[CLI] Sending list clients to server");
        let request = Request::new(empty);
        let response = self.grpc_client.list_clients(request).await?;

        println!("[CLI] Clients list response: {:?}", response);

        Ok(())
    }

    // // rpc subscribe_result(TaskId) returns (stream TaskResult) {}
    // async fn subscribe_result_to_server(&mut self, task_id: verfploeter::TaskId) -> Result<(), Box<dyn Error>> { // TODO not used (unnecessary?)
    //     let request = Request::new(task_id);
    //     let response = self.grpc_client.subscribe_result(request).await?;
    //
    //     println!("[CLI] RESPONSE = {:?}", response);
    //
    //     Ok(())
    // }
}

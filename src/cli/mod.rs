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

// Load in the CLI service and CLI Server generated code
use verfploeter::cli_server::{Cli, CliServer};
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
use std::str::FromStr;
use clap::ArgMatches;


// Struct for the CLI service
#[derive(Debug)]
pub struct CliService;

// The CLI service implementation
#[tonic::async_trait]
impl Cli for CliService {
    async fn task_finished(
         &self,
        request: Request<TaskId>,
    ) -> Result<Response<Ack>, Status> {
        unimplemented!()
    }
}

// Execute the command as part of the argument
#[tokio::main]
pub async fn execute(args: &ArgMatches) -> Result<(), Box<dyn Error>> {

    // Create client connection with the Controller Server
    println!("Connecting to Controller Server from CLI...");
    let mut client = ControllerClient::connect("http://[::1]:10001").await?;
    println!("Connected to Controller Server:");

    // list_clients_to_server(verfploeter::Empty::default(), &mut client).await;


    // If the client-list command was specified
    if args.subcommand_matches("client-list").is_some() {
        println!("Sending 'list_clients' to Server..");
        list_clients_to_server(verfploeter::Empty::default(), &mut client).await
    // If the start command was specified
    } else if let Some(matches) = args.subcommand_matches("start") {

        // Source IP for the measurement
        let source_ip: u32 =
            u32::from(Ipv4Addr::from_str(matches.value_of("SOURCE_IP").unwrap()).unwrap());

        // Get the specified IP file
        let ip_file = matches.value_of("IP_FILE").unwrap();

        // Get the destination addresses TODO hardcoded hitlist
        let file = File::open("./data/hitlist.txt").unwrap_or_else(|_| panic!("Unable to open file {}", ip_file));
        let buf_reader = BufReader::new(file);
        let ips = buf_reader
            .lines()
            .map(|l| {
                let mut address = u32::from(Ipv4Addr::from_str(&l.unwrap()).unwrap());
                address
            })
            .collect::<Vec<u32>>();
        debug!("Loaded [{}] IPAddresses on _ips vector",ips.len());
        println!("{:?}", ips);

        let schedule_task = createScheduleTask(source_ip, ips);

        do_task_to_server(schedule_task, &mut client).await

    } else {
        unimplemented!();
    }
}

// Create a verfploeter::ScheduleTask that can be sent to the server
pub fn createScheduleTask(source_address: u32, destination_addresses: Vec<u32>) -> verfploeter::ScheduleTask {
    println!("creating task");
    let task = verfploeter::ScheduleTask {
        // client: Some(verfploeter::Client {
        //     index: 1,
        //     metadata: Some(verfploeter::Metadata {
        //         hostname: "client".to_string(),
        //         version: "1".to_string(),
        //     })
        // }),
        data: Some(verfploeter::schedule_task::Data::Ping(verfploeter::Ping {
            destination_addresses,
            source_address,
        }))
    };
    println!("task created");

    task
}

// Start the CLI server

// let addr = "[::1]:10001".parse().unwrap();
//
// let cli = CliService;
//
// let svc = CliServer::new(cli);
//
// println!("CLI server listening on: {}", addr);
//
// Server::builder().add_service(svc).serve(addr).await?;
// TODO if I want to have both a server and client for CLI, then I need to handle each in separate threads
// TODO it's probably easier if I can alter the communication protocol such that there is no need for a CLI service


fn perform_measurement(args: ArgMatches) {

}

// rpc do_task(ScheduleTask) returns (Ack) {}
async fn do_task_to_server(schedule_task: verfploeter::ScheduleTask, client: &mut ControllerClient<Channel>) -> Result<(), Box<dyn Error>> {
    let request = Request::new(schedule_task);
    println!("Sending schedule task to server {:?}", request);
    let response = client.do_task(request).await?;

    println!("RESPONSE = {:?}", response);

    Ok(())
}

// rpc list_clients(Empty) returns (ClientList) {}
async fn list_clients_to_server(empty: verfploeter::Empty, client: &mut ControllerClient<Channel>) -> Result<(), Box<dyn Error>> {
    println!("Sending list clients to server");
    let request = Request::new(empty);
    let response = client.list_clients(request).await?;

    println!("RESPONSE = {:?}", response);

    Ok(())
}

// rpc subscribe_result(TaskId) returns (stream TaskResult) {}
async fn subscribe_result_to_server(task_id: verfploeter::TaskId, client: &mut ControllerClient<Channel>) -> Result<(), Box<dyn Error>> {
    let request = Request::new(task_id);
    let response = client.subscribe_result(request).await?;

    println!("RESPONSE = {:?}", response);

    Ok(())
}

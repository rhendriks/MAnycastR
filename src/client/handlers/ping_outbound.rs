#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_must_use)]


// Load in the generated code from verfploeter.proto using tonic
pub mod verfploeter {
    tonic::include_proto!("verfploeter"); // Based on the 'verfploeter' package name
}

// Load in the ControllerClient
use verfploeter::controller_client::ControllerClient;
// Load in struct definitions for the message types
use verfploeter::{
    Empty, Ack, TaskId, ScheduleTask, ClientList, Client, Metadata, Ping, Address, TaskResult,
    VerfploeterResult, PingResult,
};

use super::{Task, PingPayload};

use super::{current_timestamp, ChannelType, TaskHandler};
use crate::net::ICMP4Packet;

use futures::sync::mpsc::{channel, Receiver, Sender};
use futures::sync::oneshot;
use futures::{Future, Stream};
use ratelimit_meter::{DirectRateLimiter, LeakyBucket};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use std::u32;
use tonic::transport::Channel;
use crate::client;
// use crate::client::handlers::verfploeter::address::Value;
// use crate::client::handlers::verfploeter::task::Data::Ping;
// use super::Ping;
// use super::ControllerClient;
// use super::Task;
// use super::PingPayload;

use crate::client::handlers::verfploeter::task::Data::Ping as TaskPing;
// use crate::client::handlers::verfploeter::task::Data::Ping as TaskPing;
use crate::client::handlers::verfploeter::address::Value::V4;

const INFO_URL: &str = "edu.nl/9qt8h"; // TODO not used here?

// PingOutbound datatype
pub struct PingOutbound {
    tx: Sender<Task>,
    rx: Option<Receiver<Task>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    shutdown_rx: Option<oneshot::Receiver<()>>,
    handle: Option<JoinHandle<()>>,
    grpc_client: Arc<ControllerClient<Channel>>,
    outbound_mutex: Arc<Mutex<u32>>,
}

// TaskHandler implementation for PingOutbound
impl TaskHandler for PingOutbound {
    // Start the PingOutbound handling thread
    fn start(&mut self) {
        let handle = thread::spawn({
            let grpc_client = Arc::clone(&self.grpc_client);
            let rx = self.rx.take().unwrap();
            let shutdown_rx = self.shutdown_rx.take().unwrap();
            let outbound_mutex = Arc::clone(&self.outbound_mutex);
            move || {
                let handler = rx
                    .for_each(|i| {
                        // Start the actual pinging process in a different thread
                        // otherwise the GRPC stream will die if it takes too long
                        debug!("starting ping thread");
                        PingOutbound::start_ping_thread(
                            Arc::clone(&grpc_client),
                            Arc::clone(&outbound_mutex),
                            i,
                        );

                        futures::future::ok(())
                    })
                    .map_err(|_| error!("exiting outbound thread"));
                let poison = shutdown_rx.map_err(|_| warn!("error on shutdown_rx"));
                handler
                    .select(poison)
                    .map_err(|_| warn!("error in handler select"))
                    .wait()
                    .unwrap();
                debug!("Exiting outbound thread");
            }
        });
        self.handle = Some(handle);
    }

    // Exit/shutdown the ping_outbound thread
    fn exit(&mut self) {
        self.shutdown_tx.take().unwrap().send(()).unwrap();
        if self.handle.is_some() {
            self.handle.take().unwrap().join().unwrap();
        }
    }

    fn get_channel(&mut self) -> ChannelType {
        ChannelType::Task {
            sender: Some(self.tx.clone()),
            receiver: None,
        }
    }
}

// Implementation of PingOutbound
impl PingOutbound {
    // Return a PingOutbound object that is initialized
    pub fn new(grpc_client: Arc<ControllerClient<Channel>>) -> PingOutbound {
        let (tx, rx): (Sender<Task>, Receiver<Task>) = channel(10);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        PingOutbound {
            tx,
            rx: Some(rx),
            shutdown_tx: Some(shutdown_tx),
            shutdown_rx: Some(shutdown_rx),
            handle: None,
            grpc_client,
            outbound_mutex: Arc::new(Mutex::new(0)),
        }
    }

    // Send out the pings (called in start_ping_thread function, which is called by the start function)
    fn perform_ping(task: &Task) {

        // let ipv4addr = task.data.unwrap();
        // let TaskPing(ipv4addr) = task.data.unwrap();
        // println!("address: {:?}", ipv4addr);

        // let ipv4addr = task.data.unwrap();
        //

        let ping = if let TaskPing(ping) = task.data.unwrap() {
            ping
        }
        else {
            todo!()
        };
        let ipv4addr_src = if let Some(V4(ipv4addr_src)) = ping.source_address.unwrap().value { ipv4addr_src } else { todo!() };

        let destinations = ping.destination_addresses;

        // match task.data.unwrap() {
        //     TaskPing(ping) => println!("{:?}", ipv4addr),
        //     _ => println!("empty"),
        // }
        println!("address: {:?}", ipv4addr_src);

        info!(
            "performing outbound ping from {:?}, to {} addresses, task id: {}",
            // Ipv4Addr::from(task.get_ping().get_source_address().get_v4()),
            ipv4addr_src,
            destinations.len(),
            task.task_id,
        );
        let bindaddress = format!(
            "{}:0",
            Ipv4Addr::from(ipv4addr_src).to_string()
        );
        let socket = Socket::new(Domain::ipv4(), Type::raw(), Some(Protocol::icmpv4())).unwrap();
        socket
            .bind(
                &bindaddress
                    .to_string()
                    .parse::<SocketAddr>()
                    .unwrap()
                    .into(),
            )
            .unwrap();

        // Rate limiting
        let mut lb = DirectRateLimiter::<LeakyBucket>::per_second(NonZeroU32::new(5000).unwrap());
        for ip in destinations {
            // Create payload that will be transmitted inside the ICMP echo request

            let mut payload = PingPayload {
                task_id: task.task_id,
                transmit_time: current_timestamp(),
                source_address: ping.source_address,
                destination_address: Some(ip.clone()),
            }; //TODO fix ugly typecasting

            // let mut payload = PingPayload::new();
            // payload.set_source_address(task.get_ping().get_source_address().clone());
            // payload.set_destination_address(ip.clone());
            // payload.set_task_id(task.get_task_id());

            // Get the current time
            // payload.set_transmit_time(current_timestamp());

            let bindaddress = format!("{}:1277", Ipv4Addr::from(ipv4addr_src).to_string());
            let mut bytes: Vec<u8> = Vec::new(); // TODO transform payload to bytes

            // let bytes: Vec<u8> = payload.into();
            // let bytes = (Vec<u8>)::from(payload);
            // let bytes = match Vec<u8>::try_from(payload) {
            //     Ok()
            // }
            // Todo: make the secret configurable
            let icmp =
                ICMP4Packet::echo_request(1, 2, bytes);
                    //.to_signed_bytes("test-secret") // TODO
                    // .unwrap());

            // Rate limiter error check
            while let Err(_) = lb.check() {
                thread::sleep(Duration::from_millis(1));
                //thread::sleep(v.wait_time_from(Instant::now()));
            }

            println!("Sending out ping!");
            // Send out the packet
            if let Err(e) = socket.send_to(
                &icmp,
                &bindaddress
                    .to_string()
                    .parse::<SocketAddr>()
                    .unwrap()
                    .into(),
            ) {
                error!("Failed to send packet to socket: {:?}", e);
            //     PACKETS_TRANSMITTED_ERROR.inc();
            // } else {
            //     PACKETS_TRANSMITTED_OK.inc();
            }
        }
        debug!("finished ping");
    }

    // Start the ping thread
    fn start_ping_thread(
        grpc_client: Arc<ControllerClient<Channel>>,
        outbound_mutex: Arc<Mutex<u32>>,
        task: Task,
    ) {
        thread::spawn({
            move || {
                debug!("ping thread started");
                // Perform the ping, locking the outbound_mutex, we only
                // want one outbound ping action going at a given time
                let guard = outbound_mutex.lock().unwrap();
                debug!("start pinging (task: {})", task.task_id);
                PingOutbound::perform_ping(&task);
                debug!("stop pinging (task: {})", task.task_id);
                drop(guard);

                // Wait for a timeout
                debug!("sleeping for duration to wait for final packets");
                thread::sleep(Duration::from_secs(10));
                debug!("slept for duration to wait for final packets");

                // After finishing notify the server that the task is finished
                let mut task_id = TaskId {
                    task_id: task.task_id,
                };


                // TODO send task_finished to server
                // grpc_client
                //     .task_finished(&task_id.clone())
                //     .expect("Could not deliver task finished notification");
                //
                // debug!("finished entire ping process");
            }
        });
    }
}

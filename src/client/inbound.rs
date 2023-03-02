use std::sync::{Arc, Mutex};
use std::thread;
use socket2::{Domain, Protocol, Socket, Type};
use crate::net::{IPv4Packet, PacketPayload};
use std::net::{Ipv4Addr, Shutdown, SocketAddr};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::{Sender, UnboundedSender};
use crate::client::verfploeter::{Client, Metadata, PingPayload, PingResult, TaskResult, VerfploeterResult};
use crate::client::verfploeter::verfploeter_result::Value;


// TODO lock thread such that only one task is active at a time

// TODO socket2 can be converted into socket/stream for UDP/TCP
// This type can be freely converted into the network primitives provided by the standard library, such as TcpStream or UdpSocket, using the From trait, see the example below.

// Listen for incoming ping packets
pub fn listen_ping(socket: Arc<Socket>, tx: UnboundedSender<TaskResult>, tx_f: tokio::sync::oneshot::Sender<()>) -> Vec<JoinHandle<()>> {
    // Queue to store incoming pings, and take them out when sending the TaskResults to the server
    let result_queue = Arc::new(Mutex::new(Some(Vec::new())));

    // Handles that are used to close the spawned threads
    let mut handles = Vec::new();

    println!("[Client inbound] Started ping listener");

    // Handle for receiving the incoming pings on the socket
    let packet_receiver_handle = thread::spawn({
        let result_queue_receiver = result_queue.clone();

        let socket = socket.clone();
        move || {
           let mut buffer: Vec<u8> = vec![0; 1500];

            // Possible solutions for breaking recv
            // https://users.rust-lang.org/t/how-to-get-out-of-receiver-loop-in-channel/47314
            // https://tokio.rs/tokio/topics/shutdown
            while let Ok(result) = socket.recv(&mut buffer) { // TODO socket.recv gets stuck and never ends
               if result == 0 {
                   break;
               }

               let packet = IPv4Packet::from(&buffer[..result]);

                // Obtain the payload
                if let PacketPayload::ICMPv4 { value } = packet.payload {
                    let task_id = u32::from_be_bytes(*&value.body[0..4].try_into().unwrap());
                    // println!("task_id: {}", task_id);
                    let transmit_time = u64::from_be_bytes(*&value.body[4..12].try_into().unwrap());
                    // println!("transmit_time: {}", transmit_time);
                    let source_address = u32::from_be_bytes(*&value.body[12..16].try_into().unwrap());
                    // println!("source_address: {}", source_address);
                    let destination_address = u32::from_be_bytes(*&value.body[16..20].try_into().unwrap());
                    // println!("destination_address: {}", destination_address);

                    let receive_time = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64;

                    // Create a VerfploeterResult for the received ping reply
                    let result = VerfploeterResult {
                        value: Some(Value::Ping(PingResult {
                            source_address: u32::from(packet.source_address),
                            destination_address: u32::from(packet.destination_address),
                            receive_time,
                            payload: Some(PingPayload {
                                task_id,
                                transmit_time,
                                source_address,
                                destination_address,
                            }),
                            ttl: packet.ttl as u32,
                        })),
                    };

                    // Put result in transmission queue
                    {
                        let mut rq_opt = result_queue_receiver.lock().unwrap();
                        if let Some(ref mut x) = *rq_opt {
                            x.push(result);
                        }
                    }
                }
           }
            println!("[Client inbound] Exited socket listening thread"); // TODO these threads aren't stopped properly and remain active till forced shutdown
       }
    });

    handles.push(packet_receiver_handle);

    // Handle for sending the received pings to the server as TaskResult
    let result_sender_handle = thread::spawn({
        let result_queue_sender = result_queue.clone();

         move || {
             loop {
                 // Every 5 seconds, forward the ping results to the server
                 thread::sleep(Duration::from_secs(5));

                 // Exit the thread if client sends us the signal it's finished
                 if tx_f.is_closed() {
                     break;
                 }

                 // Get the current result queue, and replace it with an empty one
                 let mut rq;
                 {
                     let mut result_queue_sender_mutex = result_queue_sender.lock().unwrap();
                     rq = result_queue_sender_mutex.replace(Vec::new()).unwrap();
                 }

                 if rq.len() == 0 {
                     continue;
                 }

                 let tr = TaskResult {
                     task_id: 0, // TODO task_id
                     client: Some(Client {
                         index: 0, // TODO index
                         metadata: Some(Metadata {
                             hostname: "temp_hostname".to_string(),
                             version: "1.011".to_string(),
                         }),
                     }),
                     result_list: rq,
                     is_finished: false, // TODO
                 };

                 // Send the result to the client handler
                 tx.send(tr).unwrap();


             }
             // Send default value to let the rx know this is finished
             tx.send(TaskResult::default()).unwrap();
             println!("[Client inbound] Exited result handler thread");
             socket.shutdown(Shutdown::Both).unwrap();
         }
    });

    handles.push(result_sender_handle);

    // Return the handles
    handles // TODO not used?
}
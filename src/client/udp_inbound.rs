use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::thread;
use socket2::Socket;
use crate::net::{IPv4Packet, PacketPayload};
// use std::net::Shutdown;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::UnboundedSender;
use crate::client::verfploeter::{Client, Metadata, PingPayload, PingResult, TaskResult, UdpResult, VerfploeterResult};
use crate::client::verfploeter::verfploeter_result::Value;

// TODO socket2 can be converted into socket/stream for UDP/TCP
// This type can be freely converted into the network primitives provided by the standard library, such as TcpStream or UdpSocket, using the From trait, see the example below.

// Listen for incoming UDP packets
pub fn listen_udp(metadata: Metadata, socket: Arc<Socket>, tx: UnboundedSender<TaskResult>, tx_f: tokio::sync::oneshot::Sender<()>, task_id: u32, client_id: u32) {
    // Queue to store incoming UDP packets, and take them out when sending the TaskResults to the server
    let result_queue = Arc::new(Mutex::new(Some(Vec::new())));

    // Handles that are used to close the spawned threads
    let handles = Arc::new(Mutex::new(Vec::new()));

    println!("[Client inbound] Started UDP prober");

    thread::spawn({
        let result_queue_receiver = result_queue.clone();
        let handles = handles.clone();

        let socket = socket.clone();
        move || {
            let mut buffer: Vec<u8> = vec![0; 1500];

            // Tokio runtime
            let rt = tokio::runtime::Runtime::new().unwrap();
            let _enter = rt.enter();

            // Tokio thread
            let tokio_handle = rt.spawn(async move {
                println!("[Client inbound] Listening for UDP packets for task - {}", task_id);
                while let Ok(result) = socket.recv(&mut buffer) {

                    // Received when the socket closes on some OS
                    if result == 0 {
                        break;
                    }

                    // Create IPv4Packet from the bytes in the buffer
                    let packet = IPv4Packet::from(&buffer[..result]);

                    // Obtain the payload
                    if let PacketPayload::UDP { value } = packet.payload {
                        // let pkt_task_id = u32::from_be_bytes(*&value.body[0..4].try_into().unwrap());


                        // TODO make sure this UDP packet is a reply for one of our probes
                        // Make sure that this packet belongs to this task
                        // if pkt_task_id != task_id {
                        //     // If not, we discard it and await the next packet
                        //     continue
                        // }


                        // A UDP packet response will have a different body
                        // // println!("task_id: {}", task_id);
                        // let transmit_time = u64::from_be_bytes(*&value.body[4..12].try_into().unwrap());
                        // // println!("transmit_time: {}", transmit_time);
                        // let source_address = u32::from_be_bytes(*&value.body[12..16].try_into().unwrap());
                        // // println!("source_address: {}", source_address);
                        // let destination_address = u32::from_be_bytes(*&value.body[16..20].try_into().unwrap());
                        // // println!("destination_address: {}", destination_address);
                        // let sender_client_id = u32::from_be_bytes(*&value.body[20..24].try_into().unwrap());

                        let receive_time = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_nanos() as u64;

                        // Create a VerfploeterResult for the received UDP reply
                        let result = VerfploeterResult {
                            value: Some(Value::Udp(UdpResult {
                                source_address: u32::from(packet.source_address),
                                destination_address: u32::from(packet.destination_address),
                                source_port: u32::from(value.source_port),
                                destination_port: value.destination_port as u32,
                                receive_time,
                                ttl: packet.ttl as u32,
                                receiver_client_id: client_id,
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
            });
            // Push the tokio thread into the handles vec so it can be shutdown later (since socket.recv cannot be aborted)
            {
                let mut handles = handles.lock().unwrap();
                handles.push(tokio_handle);
            }
        }
    });

    // Thread for sending the received pings to the server as TaskResult
    thread::spawn({
        let result_queue_sender = result_queue.clone();
        let handles = handles.clone();

        move || {
            loop {
                // Every 5 seconds, forward the ping results to the server
                thread::sleep(Duration::from_secs(5));

                // Exit the thread if client sends us the signal it's finished
                if tx_f.is_closed() {
                    break;
                }

                // Get the current result queue, and replace it with an empty one
                let rq;
                {
                    let mut result_queue_sender_mutex = result_queue_sender.lock().unwrap();
                    rq = result_queue_sender_mutex.replace(Vec::new()).unwrap();
                }

                if rq.len() == 0 {
                    continue;
                }

                let tr = TaskResult {
                    task_id,
                    client: Some(Client {
                        // index: 0,
                        metadata: Some(metadata.clone()),
                    }),
                    result_list: rq,
                };

                // Send the result to the client handler
                tx.send(tr).unwrap();


            }
            // Send default value to let the rx know this is finished
            tx.send(TaskResult::default()).unwrap();
            // println!("[Client inbound] Exited result handler thread");
            // socket.shutdown(Shutdown::Both).unwrap();
            {
                let handles = handles.lock().unwrap();
                for handle in handles.iter() {
                    handle.abort();
                }
                println!("[Client inbound] Stopped listening for UDP packets");

            }
        }
    });
}

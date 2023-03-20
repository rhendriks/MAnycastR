use std::sync::{Arc, Mutex};
use std::thread;
use socket2::Socket;
use crate::net::{DNSARecord, IPv4Packet, PacketPayload};
// use std::net::Shutdown;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::UnboundedSender;
use crate::client::verfploeter::{Client, IPv4Result, Metadata, PingPayload, PingResult, TaskResult, VerfploeterResult, UdpPayload, UdpResult, TcpResult};
use crate::client::verfploeter::verfploeter_result::Value;

// TODO socket2 can be converted into socket/stream for UDP/TCP
// This type can be freely converted into the network primitives provided by the standard library, such as TcpStream or UdpSocket, using the From trait, see the example below.

// Listen for incoming ping packets
pub fn listen_ping(metadata: Metadata, socket: Arc<Socket>, tx: UnboundedSender<TaskResult>, tx_f: tokio::sync::oneshot::Sender<()>, task_id: u32, client_id: u8) {
    // Queue to store incoming pings, and take them out when sending the TaskResults to the server
    let result_queue = Arc::new(Mutex::new(Some(Vec::new())));

    // Handles that are used to close the spawned threads
    let handles = Arc::new(Mutex::new(Vec::new()));

    println!("[Client inbound] Started ICMP listener");

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
                println!("[Client inbound] Listening for ICMP packets for task - {}", task_id);
                while let Ok(result) = socket.recv(&mut buffer) {

                    // Received when the socket closes on some OS
                    if result == 0 {
                        break;
                    }

                    // Create IPv4Packet from the bytes in the buffer
                    let packet = IPv4Packet::from(&buffer[..result]);

                    // Obtain the payload
                    if let PacketPayload::ICMPv4 { value } = packet.payload {
                        let pkt_task_id = u32::from_be_bytes(*&value.body[0..4].try_into().unwrap());

                        // Make sure that this packet belongs to this task
                        if pkt_task_id != task_id {
                            // If not, we discard it and await the next packet
                            continue
                        }

                        let transmit_time = u64::from_be_bytes(*&value.body[4..12].try_into().unwrap());
                        let source_address = u32::from_be_bytes(*&value.body[12..16].try_into().unwrap());
                        let destination_address = u32::from_be_bytes(*&value.body[16..20].try_into().unwrap());
                        let sender_client_id = u32::from_be_bytes(*&value.body[20..24].try_into().unwrap());

                        let receive_time = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_nanos() as u64;

                        // Create a VerfploeterResult for the received ping reply
                        let result = VerfploeterResult {
                            value: Some(Value::Ping(PingResult {
                                receive_time,
                                ipv4_result: Some(IPv4Result {
                                    source_address: u32::from(packet.source_address),
                                    destination_address: u32::from(packet.destination_address),
                                    ttl: packet.ttl as u32,
                                }),
                                payload: Some(PingPayload {
                                    transmit_time,
                                    source_address,
                                    destination_address,
                                    sender_client_id,
                                }),
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
                        client_id: client_id as u32,
                        metadata: Some(metadata.clone()),
                    }),
                    result_list: rq,
                };

                // Send the result to the client handler
                tx.send(tr).unwrap();


            }
            // Send default value to let the rx know this is finished
            tx.send(TaskResult::default()).unwrap();
            {
                let handles = handles.lock().unwrap();
                for handle in handles.iter() {
                    handle.abort();
                }
                println!("[Client inbound] Stopped listening for ICMP packets");

            }
        }
    });
}

// Listen for incoming UDP packets
pub fn listen_udp(metadata: Metadata, socket: Arc<Socket>, tx: UnboundedSender<TaskResult>, tx_f: tokio::sync::oneshot::Sender<()>, task_id: u32, client_id: u8, sender_src_port: u16) {
    // Queue to store incoming UDP packets, and take them out when sending the TaskResults to the server
    let result_queue = Arc::new(Mutex::new(Some(Vec::new())));

    // Handles that are used to close the spawned threads
    let handles = Arc::new(Mutex::new(Vec::new()));

    println!("[Client inbound] Started UDP listener");

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
                while let Ok(result) = socket.recv(&mut buffer) { // TODO does not get closed
                    println!("result: {:?}", result);

                    // Received when the socket closes on some OS
                    if result == 0 {
                        break;
                    }

                    // Create IPv4Packet from the bytes in the buffer
                    let packet = IPv4Packet::from(&buffer[..result]);

                    // Obtain the payload
                    if let PacketPayload::UDP { value } = packet.payload {
                        // The UDP responses will be from DNS services, with port 53 and our src port as dest port
                        if (value.source_port != 53) | (value.destination_port != sender_src_port) {
                            continue
                        }

                        let receive_time = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_nanos() as u64;

                        // TODO what if the response does not have a body that can be transformed into a DNSARecord
                        let record = DNSARecord::from(value.body.as_slice());

                        let domain = record.domain; // example: '1679305276037913215-3226971181-16843009-0-4000.google.com'

                        // Get the information from the domain, continue to the next packet if it does not follow the format
                        let parts: Vec<&str> = domain.split('.').next().unwrap().split('-').collect();
                        let transmit_time = match parts[0].parse::<u64>() {
                            Ok(t) => t,
                            Err(_) => continue,
                        };
                        let sender_src = match parts[1].parse::<u32>() {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        let sender_dest = match parts[2].parse::<u32>() {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        let sender_client_id = match parts[3].parse::<u8>() {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        let sender_src_port = match parts[4].parse::<u16>() {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        // let domain = domain.split('.').skip(1).next().unwrap();

                        // Create a VerfploeterResult for the received UDP reply
                        let result = VerfploeterResult {
                            value: Some(Value::Udp(UdpResult {
                                source_port: u32::from(value.source_port),
                                destination_port: value.destination_port as u32,
                                ipv4_result: Some(IPv4Result {
                                    source_address: u32::from(packet.source_address),
                                    destination_address: u32::from(packet.destination_address),
                                    ttl: packet.ttl as u32,
                                }),
                                receive_time,
                                payload: Some(UdpPayload {
                                    transmit_time,
                                    source_address: sender_src,
                                    destination_address: sender_dest,
                                    sender_client_id: sender_client_id as u32,
                                    source_port: sender_src_port as u32,
                                }),
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
                        client_id: client_id as u32,
                        metadata: Some(metadata.clone()),
                    }),
                    result_list: rq,
                };

                // Send the result to the client handler
                tx.send(tr).unwrap();


            }
            // Send default value to let the rx know this is finished
            tx.send(TaskResult::default()).unwrap();
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

// Listen for incoming TCP packets
pub fn listen_tcp(metadata: Metadata, socket: Arc<Socket>, tx: UnboundedSender<TaskResult>, tx_f: tokio::sync::oneshot::Sender<()>, task_id: u32, client_id: u8) {
    // Queue to store incoming TCP packets, and take them out when sending the TaskResults to the server
    let result_queue = Arc::new(Mutex::new(Some(Vec::new())));

    // Handles that are used to close the spawned threads
    let handles = Arc::new(Mutex::new(Vec::new()));

    println!("[Client inbound] Started TCP prober");

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
                println!("[Client inbound] Listening for TCP packets for task - {}", task_id);
                while let Ok(result) = socket.recv(&mut buffer) {

                    // Received when the socket closes on some OS
                    if result == 0 {
                        break;
                    }

                    // Create IPv4Packet from the bytes in the buffer
                    let packet = IPv4Packet::from(&buffer[..result]);

                    // Obtain the payload
                    if let PacketPayload::TCP { value } = packet.payload {
                        // Responses to our probes have destination port > 4000 (as we use these as source)
                        // Use the RST flag, and have ACK 0
                        if (value.destination_port < 4000) | (value.flags != 0b00000100) | (value.ack != 0) {
                            continue
                        }

                        let receive_time = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_nanos() as u64;

                        // Create a VerfploeterResult for the received UDP reply
                        let result = VerfploeterResult {
                            value: Some(Value::Tcp(TcpResult {
                                source_port: u32::from(value.source_port),
                                destination_port: value.destination_port as u32,
                                seq: value.seq,
                                ipv4_result: Some(IPv4Result {
                                    source_address: u32::from(packet.source_address),
                                    destination_address: u32::from(packet.destination_address),
                                    ttl: packet.ttl as u32,
                                }),
                                receive_time,
                                ack: value.ack,
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
                        client_id: client_id as u32,
                        metadata: Some(metadata.clone()),
                    }),
                    result_list: rq,
                };

                // Send the result to the client handler
                tx.send(tr).unwrap();


            }
            // Send default value to let the rx know this is finished
            tx.send(TaskResult::default()).unwrap();
            {
                let handles = handles.lock().unwrap();
                for handle in handles.iter() {
                    handle.abort();
                }
                println!("[Client inbound] Stopped listening for TCP packets");

            }
        }
    });
}


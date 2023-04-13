use std::net::Shutdown;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use socket2::Socket;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot::Sender;
use crate::client::verfploeter::{Client, IPv4Result, Metadata, PingPayload, PingResult, TaskResult, TcpResult, UdpPayload, UdpResult, verfploeter_result::Value, VerfploeterResult};
use crate::net::{DNSARecord, IPv4Packet, PacketPayload};

/// Listen for incoming ping/ICMP packets, these packets must have our payload to be considered valid replies.
///
/// Creates two threads, one that listens on the socket and another that forwards results to the server and shuts down the receiving socket when appropriate.
///
/// For a received packet to be considered a reply, it must be an ICMP packet with the current task ID in the first 4 bytes of the ICMP payload.
/// From these replies it creates task results that are put in a result queue, which get sent to the server.
///
/// # Arguments
///
/// * 'metadata' - contains the metadata of this listening client (the hostname and client ID)
///
/// * 'socket' - the socket to listen on
///
/// * 'tx' - sender to put task results in
///
/// * 'tx_f' - channel that gets closed when the outbound prober is finished for the current measurement
///
/// * 'task_id' - the task_id of the current measurement
///
/// * 'client_id' - the unique client ID of this client
pub fn listen_ping(metadata: Metadata, socket: Arc<Socket>, tx: UnboundedSender<TaskResult>, tx_f: Sender<()>, task_id: u32, client_id: u8) {
    // Result queue to store incoming pings, and take them out when sending the TaskResults to the server
    let rq = Arc::new(Mutex::new(Some(Vec::new())));
    println!("[Client inbound] Started ICMP listener");

    thread::spawn({
        let rq_receiver = rq.clone();

        let socket = socket.clone();
        move || {
            let mut buffer: Vec<u8> = vec![0; 1500];
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
                    let s = if let Ok(s) = *&value.body[0..4].try_into() { s } else { continue; };

                    let pkt_task_id = u32::from_be_bytes(s);

                    // Make sure that this packet belongs to this task
                    if (pkt_task_id != task_id) | (value.body.len() < 24) {
                        // If not, we discard it and await the next packet
                        continue;
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
                        let mut rq_opt = rq_receiver.lock().unwrap();
                        if let Some(ref mut x) = *rq_opt {
                            x.push(result);
                        }
                    }
                }
            }
            println!("[Client inbound] Stopped listening on socket");
        }
    });

    // Thread for sending the received replies to the server as TaskResult
    thread::spawn({
        let result_queue_sender = rq.clone();
        move || {
            handle_results(metadata, &tx, tx_f, task_id, client_id, result_queue_sender);

            // Send default value to let the rx know this is finished
            tx.send(TaskResult::default()).unwrap();
            match socket.shutdown(Shutdown::Read) {
                Err(_) => println!("[Client inbound] Shut down socket erroneously"),
                _ => println!("[Client inbound] Shut down socket"),
            }
            println!("[Client inbound] Stopped listening for ICMP packets");
        }
    });
}

/// Listen for incoming UDP DNS packets,
/// these packets must have a DNS A record reply and use the correct port numbers to be considered a reply.
///
/// Creates two threads, one that listens on the socket and another that forwards results to the server and shuts down the receiving socket when appropriate.
///
/// For a received packet to be considered a reply, it must be an UDP DNS packet that contains an A record that follows a specific format.
/// From these replies it creates task results that are put in a result queue, which get sent to the server.
///
/// # Arguments
///
/// * 'metadata' - contains the metadata of this listening client (the hostname)
///
/// * 'socket' - the socket to listen on
///
/// * 'tx' - sender to put task results in
///
/// * 'tx_f' - channel that gets closed when the outbound prober is finished for the current measurement
///
/// * 'task_id' - the task_id of the current measurement
///
/// * 'client_id' - the unique client ID of this client
///
/// * 'sender_src_port' - the source port used in the probes (destination port of received reply must match this value)
pub fn listen_udp(metadata: Metadata, socket: Arc<Socket>, tx: UnboundedSender<TaskResult>, tx_f: Sender<()>, task_id: u32, client_id: u8, sender_src_port: u16) {
    // Queue to store incoming UDP packets, and take them out when sending the TaskResults to the server
    let result_queue = Arc::new(Mutex::new(Some(Vec::new())));
    println!("[Client inbound] Started UDP listener");

    thread::spawn({
        let result_queue_receiver = result_queue.clone();

        let socket = socket.clone();
        move || {
            let mut buffer: Vec<u8> = vec![0; 1500];
            println!("[Client inbound] Listening for UDP packets for task - {}", task_id);
            while let Ok(result) = socket.recv(&mut buffer) {
                // Received when the socket closes on some OS
                if result == 0 {
                    break;
                }

                // Create IPv4Packet from the bytes in the buffer
                let packet = IPv4Packet::from(&buffer[..result]);
                println!("received {:?}", packet); // TODO check if we also receive the ICMP port unreachable packets on this port
                // TODO if not create new socket listening thread that listens for ICMP

                // Obtain the payload
                if let PacketPayload::UDP { value } = packet.payload {
                    // The UDP responses will be from DNS services, with port 53 and our src port as dest port, furthermore the body length has to be large enough to contain a DNS A reply
                    if (value.source_port != 53) | (value.destination_port != sender_src_port) | (value.body.len() < 66) {
                        continue;
                    }

                    let receive_time = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64;
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
            println!("[Client inbound] Stopped listening on socket");
        }
    });

    // Thread for sending the received replies to the server as TaskResult
    thread::spawn({
        let result_queue_sender = result_queue.clone();

        move || {
            handle_results(metadata, &tx, tx_f, task_id, client_id, result_queue_sender);

            // Send default value to let the rx know this is finished
            tx.send(TaskResult::default()).unwrap();
            socket.shutdown(Shutdown::Read).unwrap_err();
            println!("[Client inbound] Stopped listening for UDP packets");
        }
    });
}

/// Listen for incoming TCP/RST packets, these packets must have the correct destination port,
/// have the right flags set (RST), and have ACK == 0 for it to be considered a reply.
///
/// Creates two threads, one that listens on the socket and another that forwards results to the server and shuts down the receiving socket when appropriate.
///
/// For a received packet to be considered a reply, it must be a TCP packet with the RST flag set and using the correct port numbers.
/// From these replies it creates task results that are put in a result queue, which get sent to the server.
///
/// # Arguments
///
/// * 'metadata' - contains the metadata of this listening client (the hostname)
///
/// * 'socket' - the socket to listen on
///
/// * 'tx' - sender to put task results in
///
/// * 'tx_f' - channel that gets closed when the outbound prober is finished for the current measurement
///
/// * 'task_id' - the task_id of the current measurement
///
/// * 'client_id' - the unique client ID of this client
pub fn listen_tcp(metadata: Metadata, socket: Arc<Socket>, tx: UnboundedSender<TaskResult>, tx_f: Sender<()>, task_id: u32, client_id: u8) {
    // Queue to store incoming TCP packets, and take them out when sending the TaskResults to the server
    let result_queue = Arc::new(Mutex::new(Some(Vec::new())));

    println!("[Client inbound] Started TCP prober");

    thread::spawn({
        let result_queue_receiver = result_queue.clone();
        let socket = socket.clone();

        move || {
            let mut buffer: Vec<u8> = vec![0; 1500];

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
                        continue;
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
            println!("[Client inbound] Stopped listening on socket");
        }
    });

    // Thread for sending the received replies to the server as TaskResult
    thread::spawn({
        let result_queue_sender = result_queue.clone();

        move || {
            handle_results(metadata, &tx, tx_f, task_id, client_id, result_queue_sender);
            // Send default value to let the rx know this is finished
            tx.send(TaskResult::default()).unwrap();
            socket.shutdown(Shutdown::Read).unwrap_err();
            println!("[Client inbound] Stopped listening for TCP packets");
        }
    });
}

/// Thread for handling the received replies, wrapping them in a TaskResult, and streaming them back to the main client class.
///
/// # Arguments
///
/// * 'metadata' - contains the metadata of this listening client (the hostname)
///
/// * 'tx' - sender to put task results in
///
/// * 'tx_f' - channel that gets closed when the outbound prober is finished for the current measurement
///
/// * 'task_id' - the task_id of the current measurement
///
/// * 'client_id' - the unique client ID of this client
///
/// * 'result_queue_sender' - contains a vector of all received replies as VerfploeterResult
fn handle_results(metadata: Metadata, tx: &UnboundedSender<TaskResult>, tx_f: Sender<()>, task_id: u32, client_id: u8, result_queue_sender: Arc<Mutex<Option<Vec<VerfploeterResult>>>>) {
    loop {
        // Every 5 seconds, forward the ping results to the server
        thread::sleep(Duration::from_secs(5));

        // Get the current result queue, and replace it with an empty one
        let rq;
        {
            let mut rq_mutex = result_queue_sender.lock().unwrap();
            rq = rq_mutex.replace(Vec::new()).unwrap();
        }

        // If we have an empty result queue
        if rq.len() == 0 {
            // Exit the thread if client sends us the signal it's finished
            if tx_f.is_closed() {
                break;
            }
            continue;
        }

        let tr = TaskResult {
            task_id,
            client: Some(Client {
                client_id: client_id as u32,
                metadata: Some(metadata.clone()),
            }),
            result_list: rq,
        };

        // Send the result to the client handler
        tx.send(tr).unwrap();
    }
}
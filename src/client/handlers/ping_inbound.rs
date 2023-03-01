// // Load in the generated code from verfploeter.proto using tonic
// pub mod verfploeter {
//     tonic::include_proto!("verfploeter"); // Based on the 'verfploeter' package name
// }
//
// // Load in the ControllerClient
// use verfploeter::controller_client::ControllerClient;
// // Load in struct definitions for the message types
// use verfploeter::{
//     Empty, Ack, TaskId, ScheduleTask, ClientList, Client, Task, Metadata, Ping, Address, TaskResult,
//     VerfploeterResult, PingResult, PingPayload,
// };
//
// use super::{current_timestamp, ChannelType, TaskHandler};
// use futures::sync::oneshot;
//
//
//
// // PingInbound type, which contains handles (for multi-threading), a socket, the grpc_client,
// // Metadata, a result queue, a receiver, and a sender.
// pub struct PingInbound {
//     handles: Vec<JoinHandle<()>>,
//     socket: Arc<Socket>,
//     grpc_client: Arc<ControllerClient>, // TODO https://rust.velas.com/tonic/client/ apparently the client can simply be cloned and passed on to here
//     metadata: Metadata,
//     result_queue: Arc<Mutex<Option<Vec<Result>>>>,
//     poison_rx: oneshot::Receiver<()>,
//     poison_tx: Option<oneshot::Sender<()>>,
// }
//
// // Implement TaskHandler for PingInbound
// impl TaskHandler for PingInbound {
//     // Starts the PingInbound, which receives packets and puts them in a channel for processing.
//     fn start(&mut self) {
//         let (tx, rx) = channel(1024);
//
//         // The packet receiver thread takes the packets from the actual socket
//         // and puts them in a channel to be processed
//         let packet_receiver_handle = thread::spawn({
//             let socket = self.socket.clone();
//             move || {
//                 let mut buffer: Vec<u8> = vec![0; 1500];
//                 while let Ok(result) = socket.recv(&mut buffer) {
//                     PACKETS_RECEIVED.inc();
//                     if result == 0 {
//                         break;
//                     }
//
//                     let packet = IPv4Packet::from(&buffer[..result]);
//                     tx.clone()
//                         .send((current_timestamp(), packet))
//                         .wait()
//                         .expect("unable to send packet to tx channel");
//                 }
//             }
//         });
//
//         // The packet processor thread takes the packets from the packet receiver thread channel
//         // processes them (check the payload, create the protobuf struct) and puts them in a
//         // buffer for transmission to the server
//         let packet_processor_handle = thread::spawn({
//             let result_queue = self.result_queue.clone();
//             move || {
//                 rx.for_each(|(receive_time, packet)| {
//                     // Extract payload
//                     let mut ping_payload = None;
//                     if let PacketPayload::ICMPv4 { value } = packet.payload {
//                         // Todo: make the secret configurable
//                         if value.body.len() >= 60 {
//                             let payload =
//                                 PingPayload::from_signed_bytes("test-secret", &value.body[0..60]);
//                             if let Ok(payload) = payload {
//                                 ping_payload = Some(payload);
//                             } else {
//                                 warn!("invalid payload from {}", packet.source_address);
//                             }
//                         }
//                     } else {
//                         warn!("invalid payload from {}", packet.source_address);
//                     }
//
//                     // Don't do anything if we don't have a proper payload
//                     if ping_payload.is_none() {
//                         PACKETS_PROCESSED_INVALID.inc();
//                         return futures::future::ok(());
//                     }
//                     PACKETS_PROCESSED_VALID.inc();
//                     let ping_payload = ping_payload.unwrap();
//
//                     let mut result = Result::new();
//                     let mut pr = PingResult::new();
//
//                     pr.set_payload(ping_payload);
//                     pr.set_source_address(packet.source_address.into());
//                     pr.set_destination_address(packet.destination_address.into());
//                     pr.set_receive_time(receive_time);
//                     pr.set_ttl(packet.ttl.into());
//                     result.set_ping(pr);
//
//                     // Put result in transmission queue
//                     {
//                         let mut rq_opt = result_queue.lock().unwrap();
//                         if let Some(ref mut x) = *rq_opt {
//                             x.push(result);
//                         }
//                     }
//
//                     futures::future::ok(())
//                 })
//                     .map_err(|_| ())
//                     .wait()
//                     .unwrap();
//             }
//         });
//
//         // The packet transmitter thread periodically swaps out the buffer the packet processor
//         // writes its results to and starts transmitting the data
//         let packet_transmitter_handle = thread::spawn({
//             let grpc_client = self.grpc_client.clone();
//             let result_queue = self.result_queue.clone();
//             let poison_tx = self.poison_tx.take().unwrap();
//             let metadata = self.metadata.clone();
//             move || {
//                 loop {
//                     thread::sleep(Duration::from_secs(5));
//
//                     // Check if this thread is still supposed to be running
//                     if poison_tx.is_canceled() {
//                         break;
//                     }
//
//                     // Get the current result queue, and replace it with an empty one
//                     let mut rq;
//                     {
//                         let mut result_queue = result_queue.lock().unwrap();
//                         rq = result_queue.replace(Vec::new()).unwrap();
//                     }
//
//                     // Sort the result queue by task id
//                     let mut rq_ping = rq.drain_filter(|x| x.has_ping()).collect::<Vec<Result>>();
//                     rq_ping.sort_by_key(|x| x.get_ping().get_payload().get_task_id());
//
//                     // Transmit the results, grouped by task id
//                     let mut tr = TaskResult::new();
//                     tr.set_task_id(u32::MAX);
//                     for result in rq_ping {
//                         let result_taskid = result.get_ping().get_payload().get_task_id();
//                         if tr.get_task_id() != result_taskid {
//                             // If the current 'result container' has some results, send it
//                             if !tr.get_result_list().is_empty() {
//                                 if let Err(e) = grpc_client.send_result(&tr) {
//                                     error!("failed to send result to server: {}", e);
//                                 } else {
//                                     PACKETS_TRANSMITTED.inc_by(tr.get_result_list().len() as i64);
//                                 }
//                             }
//                             tr = TaskResult::new();
//                             tr.set_task_id(result_taskid);
//                             let mut client = Client::new();
//                             client.set_metadata(metadata.clone());
//                             tr.set_client(client);
//                         }
//                         tr.mut_result_list().push(result);
//                     }
//                     if !tr.get_result_list().is_empty() {
//                         if let Err(e) = grpc_client.send_result(&tr) {
//                             error!("failed to send result to server: {}", e);
//                         } else {
//                             PACKETS_TRANSMITTED.inc_by(tr.get_result_list().len() as i64);
//                         }
//                     }
//                 }
//             }
//         });
//         self.handles.push(packet_receiver_handle);
//         self.handles.push(packet_processor_handle);
//         self.handles.push(packet_transmitter_handle);
//     }
//
//     fn exit(&mut self) {
//         self.socket.shutdown(Shutdown::Both).unwrap_err();
//         self.poison_rx.close();
//         for handle in self.handles.drain(..) {
//             handle.join().unwrap();
//         }
//     }
//
//     fn get_channel(&mut self) -> ChannelType {
//         ChannelType::None
//     }
// }
//
// impl PingInbound {
//     pub fn new(metadata: Metadata, grpc_client: Arc<VerfploeterClient>) -> PingInbound {
//         let socket =
//             Arc::new(Socket::new(Domain::ipv4(), Type::raw(), Some(Protocol::icmpv4())).unwrap());
//         let (poison_tx, poison_rx): (oneshot::Sender<()>, oneshot::Receiver<()>) =
//             oneshot::channel();
//
//         PingInbound {
//             handles: Vec::new(),
//             socket,
//             grpc_client,
//             metadata,
//             result_queue: Arc::new(Mutex::new(Some(Vec::new()))),
//             poison_tx: Some(poison_tx),
//             poison_rx,
//         }
//     }
// }
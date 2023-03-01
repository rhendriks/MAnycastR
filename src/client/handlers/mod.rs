// Load in the generated code from verfploeter.proto using tonic
// pub mod verfploeter {
//     tonic::include_proto!("verfploeter"); // Based on the 'verfploeter' package name
// }
//
// // Load in the ControllerClient
// use verfploeter::controller_client::ControllerClient;
// // Load in struct definitions for the message types
// use verfploeter::{
//     Task, PingPayload
// };

// pub mod ping_inbound;
// pub mod ping_outbound;

use super::Task;

pub mod inbound;
pub mod outbound;

// Load in the generated code from verfploeter.proto using tonic
// pub mod verfploeter {
//     tonic::include_proto!("verfploeter"); // Based on the 'verfploeter' package name
// }
//
// // Load in struct definitions for the message types
// use verfploeter::Task;
use futures::sync::mpsc::{Receiver, Sender};

// use super::{Receiver, Sender, Ping, ControllerClient, Task};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::client::verfploeter::PingPayload;

// ChannelType. Which contains a sender and receiver
pub enum ChannelType {
    Task {
        sender: Option<Sender<Task>>,
        receiver: Option<Receiver<Task>>,
    },
    None,
}

// TaskHandler interface, has a start, exit, and get_channel function.
pub trait TaskHandler {
    fn start(&mut self);
    fn exit(&mut self);
    fn get_channel(&mut self) -> ChannelType;
}

// Gets the current timestamp
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

impl From<Vec<u8>> for PingPayload {
    fn from(bytes: Vec<u8>) -> Self {

        todo!()
    }
}
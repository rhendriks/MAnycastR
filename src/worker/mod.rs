use clap::ArgMatches;
use gethostname::gethostname;
use std::error::Error;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

pub(crate) use crate::worker::config::Worker;
use pnet::datalink::Channel as SocketChannel;

mod client;
mod config;
mod inbound;
mod measurement;
mod outbound;

impl Worker {
    /// Create a worker instance, which includes establishing a connection with the orchestrator.
    ///
    /// Extracts the parameters of the command-line arguments.
    ///
    /// # Arguments
    ///
    /// * 'args' - contains the parsed command-line arguments
    pub async fn new(args: &ArgMatches) -> Result<Worker, Box<dyn Error>> {
        // Get hostname from command line arguments or use the system hostname
        let hostname = args
            .get_one::<String>("hostname")
            .map(|h| h.parse::<String>().expect("Unable to parse hostname"))
            .unwrap_or_else(|| gethostname().into_string().expect("Unable to get hostname"));

        let orc_addr = args.get_one::<String>("orchestrator").unwrap();
        let fqdn = args.get_one::<String>("tls");
        let client = Worker::connect(orc_addr.parse().unwrap(), fqdn)
            .await
            .expect("Unable to connect to orchestrator");
        
        let interface = if args.contains_id("interface") {
            args.get_one::<String>("interface").map(|i| i.to_string())
        } else {
            None
        };

        // Initialize a worker instance
        let mut worker = Worker {
            grpc_client: client,
            hostname,
            current_m_id: Arc::new(Mutex::new(None)),
            outbound_tx: None,
            abort_s: Arc::new(AtomicBool::new(false)),
            interface,
        };

        worker.connect_to_server().await?;

        Ok(worker)
    }
}

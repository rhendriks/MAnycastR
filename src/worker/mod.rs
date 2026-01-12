use clap::ArgMatches;
use gethostname::gethostname;
use std::error::Error;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

pub(crate) use crate::worker::config::Worker;

mod client;
mod config;
mod inbound;
mod measurement;
mod outbound;

impl Worker {
    /// Create a worker instance, which includes establishing a connection with the orchestrator.
    ///
    /// # Arguments
    /// * `args` - contains the parsed command-line arguments
    pub async fn new(args: &ArgMatches) -> Result<Worker, Box<dyn Error>> {
        // Get hostname from command line arguments or use the system hostname
        let hostname = args
            .get_one::<String>("hostname")
            .map(|h| h.parse::<String>().expect("Unable to parse hostname"))
            .unwrap_or_else(|| gethostname().into_string().expect("Unable to get hostname"));

        let orc_addr = args.get_one::<String>("orchestrator").unwrap();
        let fqdn = args.get_one::<String>("tls").map(String::as_str);
        let grpc_client = Self::connect(orc_addr.parse()?, fqdn).await?;

        // Initialize a worker instance
        let mut worker = Self {
            grpc_client,
            hostname,
            current_m_id: Arc::new(Mutex::new(None)),
            outbound_txs: vec![],
            abort_inbound: Arc::new(AtomicBool::new(false)),
        };

        worker.connect_to_server().await?;

        Ok(worker)
    }
}

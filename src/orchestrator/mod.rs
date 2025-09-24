mod worker;
mod cli;
mod service;
mod config;
mod task_distributor;

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::ops::AddAssign;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::custom_module;
use crate::custom_module::manycastr::Address;
use crate::orchestrator::mpsc::Sender;
use clap::ArgMatches;
use custom_module::manycastr::{
    controller_server::ControllerServer, Task, TaskResult,
};
use log::{info, warn};
use rand::Rng;
use tokio::sync::mpsc;
use tonic::codec::CompressionEncoding;
use tonic::transport::ServerTlsConfig;
use tonic::{transport::Server, Status};
use crate::orchestrator::config::{load_tls, load_worker_config};
use crate::orchestrator::worker::WorkerSender;

type ResultMessage = Result<TaskResult, Status>;
type CliSender = Sender<ResultMessage>;
type CliHandle = Arc<Mutex<Option<CliSender>>>;

type TaskMessage = Result<Task, Status>;

const BREAK_SIGNAL: u32 = u32::MAX - 1;
const ALL_WORKERS_DIRECT: u32 = u32::MAX;
const ALL_WORKERS_INTERVAL: u32 = u32::MAX - 2;

/// The main orchestrator service struct.
#[derive(Debug)]
pub struct ControllerService {
    /// List of connected workers
    workers: Arc<Mutex<Vec<WorkerSender<TaskMessage>>>>,
    /// Sender to the CLI for streaming results
    cli_sender: CliHandle,
    /// Open measurements and their active worker counts
    open_measurements: Arc<Mutex<HashMap<u32, u32>>>,
    /// Last used measurement ID
    m_id: Arc<Mutex<u32>>,
    /// Last used unique worker ID
    unique_id: Arc<Mutex<u32>>,
    /// Indicates if a measurement is currently active
    is_active: Arc<Mutex<bool>>,
    /// Indicates if the orchestrator is in responsive probing mode
    is_responsive: Arc<AtomicBool>,
    /// Indicates if the orchestrator is in latency probing mode
    is_latency: Arc<AtomicBool>,
    /// Optional static mapping of hostnames to worker IDs
    worker_config: Option<HashMap<String, u32>>,
    /// Stacks of addresses for each worker, used for follow-up probes
    worker_stacks: Arc<Mutex<HashMap<u32, VecDeque<Address>>>>,
}

impl ControllerService {
    /// Gets a unique worker ID for a new connecting worker.
    /// Increments the unique ID counter after returning the ID (for the next worker).
    fn get_unique_id(&self) -> u32 {
        let mut unique_id = self.unique_id.lock().unwrap();
        let worker_id = *unique_id;
        unique_id.add_assign(1);

        worker_id
    }

    /// Gets a worker ID for a connecting worker based on its hostname.
    /// If the hostname already exists, it returns the existing worker ID.
    /// If the hostname does not exist, it checks for a statically configured ID or generates a new unique ID.
    ///
    /// # Arguments
    /// * 'hostname' - the hostname of the worker
    ///
    /// # Returns
    /// Returns a tuple containing: the worker ID and a boolean indicating if this is a reconnection of a closed worker.
    ///
    /// # Errors
    /// Returns an error if the hostname already exists and is used by a connected worker.
    fn get_worker_id(&self, hostname: &str) -> Result<(u32, bool), Box<Status>> {
        {
            let workers = self.workers.lock().unwrap();
            // Check if the hostname already exists in the workers list
            if let Some(existing_worker) = workers.iter().find(|w| w.hostname == hostname) {
                return if !existing_worker.is_closed() {
                    warn!(
                        "[Orchestrator] Refusing worker as the hostname already exists: {hostname}"
                    );
                    Err(Box::new(Status::already_exists(
                        "This hostname already exists",
                    )))
                } else {
                    // This is a reconnection of a closed worker.
                    let id = existing_worker.worker_id;
                    Ok((id, true))
                };
            }
        }

        // Check for a statically configured ID
        if let Some(worker_config) = &self.worker_config {
            if let Some(worker_id) = worker_config.get(hostname) {
                return Ok((*worker_id, false));
            }
        }

        // Return a new unique ID
        let new_id = self.get_unique_id();
        Ok((new_id, false))
    }
}

/// Starts the orchestrator on the specified port.
///
/// # Arguments
///
/// * 'args' - the parsed command-line arguments
pub async fn start(args: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let port = *args.get_one::<u16>("port").unwrap();
    let addr: SocketAddr = format!("[::]:{port}").parse().unwrap();

    // Get optional configuration file
    let (current_worker_id, worker_config) = args
        .get_one::<String>("config")
        .map(load_worker_config)
        .unwrap_or_else(|| (Arc::new(Mutex::new(1)), None));

    // Get a random measurement ID to start with
    let m_id = rand::rng().random_range(0..u32::MAX);

    let controller = ControllerService {
        workers: Arc::new(Mutex::new(Vec::new())),
        cli_sender: Arc::new(Mutex::new(None)),
        open_measurements: Arc::new(Mutex::new(HashMap::new())),
        m_id: Arc::new(Mutex::new(m_id)),
        unique_id: current_worker_id,
        is_active: Arc::new(Mutex::new(false)),
        is_responsive: Arc::new(AtomicBool::new(false)),
        is_latency: Arc::new(AtomicBool::new(false)),
        worker_config,
        worker_stacks: Arc::new(Mutex::new(HashMap::new())),
    };

    let svc = ControllerServer::new(controller)
        .accept_compressed(CompressionEncoding::Zstd)
        .max_decoding_message_size(10 * 1024 * 1024 * 1024) // 10 GB
        .max_encoding_message_size(10 * 1024 * 1024 * 1024);

    // if TLS is enabled create the orchestrator using a TLS configuration
    if args.get_flag("tls") {
        info!("[Orchestrator] Starting orchestrator with TLS enabled");
        Server::builder()
            .tls_config(ServerTlsConfig::new().identity(load_tls()))
            .expect("Failed to load TLS certificate")
            .http2_keepalive_interval(Some(Duration::from_secs(10)))
            .http2_keepalive_timeout(Some(Duration::from_secs(20)))
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .add_service(svc)
            .serve(addr)
            .await
            .expect("Failed to start orchestrator with TLS");
    } else {
        Server::builder()
            .http2_keepalive_interval(Some(Duration::from_secs(10)))
            .http2_keepalive_timeout(Some(Duration::from_secs(20)))
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .add_service(svc)
            .serve(addr)
            .await
            .expect("Failed to start orchestrator");
    }

    Ok(())
}

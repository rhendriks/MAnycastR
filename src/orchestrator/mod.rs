mod cli;
mod config;
mod result_handler;
mod service;
mod task_distributor;
mod trace;
mod worker;

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::ops::AddAssign;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::custom_module;
use crate::orchestrator::config::{load_tls, load_worker_config};
use crate::orchestrator::mpsc::Sender;
use crate::orchestrator::result_handler::SessionTracker;
use crate::orchestrator::worker::WorkerSender;
use clap::ArgMatches;
use custom_module::manycastr::{
    controller_server::ControllerServer, Instruction, ReplyBatch, Task,
};
use log::{info, warn};
use tokio::sync::mpsc;
use tonic::codec::CompressionEncoding;
use tonic::transport::ServerTlsConfig;
use tonic::{transport::Server, Status};

type ResultMessage = Result<ReplyBatch, Status>;
type CliSender = Sender<ResultMessage>;
type CliHandle = Arc<Mutex<Option<CliSender>>>;

type TaskMessage = Result<Instruction, Status>;

const BREAK_SIGNAL: u32 = u32::MAX - 1;
const ALL_WORKERS_DIRECT: u32 = u32::MAX;
const ALL_WORKERS_INTERVAL: u32 = u32::MAX - 2;

/// The measurement types that result in different result handling behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeasurementType {
    /// Targets are probed for responsiveness from any worker, measurement probes are sent from all workers.
    Responsive,
    /// Targets are probed to determine the catching worker, measurement probes are sent from the catching worker.
    Latency,
    /// Targets are probed to determine the catching worker, traceroute probes are sent from the catching worker.
    Traceroute,
}

/// State to keep track of an ongoing measurement
#[derive(Debug)]
pub struct OngoingMeasurement {
    /// Number of Workers still participating in the measurement (decremented when a Worker finishes)
    workers_count: u32,
    /// Worker IDs of connected Workers that are actively probing
    probing_workers: Vec<u32>,
}

/// Traceroute configuration
#[derive(Debug)]
pub struct TracerouteConfig {
    /// Session tracker for Trace Tasks
    pub session_tracker: SessionTracker,
    /// Timeout value for traceroute measurements (default 1s)
    pub timeout: u64,
    /// Max hop count for traceroute measurements (default 30)
    pub max_hops: u32,
    /// Hop count to start traceroute measurements with (default 1)
    pub initial_hop: u32,
    /// Maximum number of unresponsive hops before terminating the traceroute (default 3)
    pub max_failures: u32,
}

/// The main orchestrator service struct.
#[derive(Debug)]
pub struct ControllerService {
    /// List of connected workers
    saved_workers: Arc<Mutex<Vec<WorkerSender<TaskMessage>>>>,
    /// Sender to the CLI for streaming results
    cli_sender: CliHandle,
    /// Number of workers participating in the current measurement (None if no measurement is active)
    //workers_count: Arc<Mutex<Option<u32>>>,
    ongoing_measurement: Arc<RwLock<Option<OngoingMeasurement>>>,
    /// Last used unique worker ID
    unique_id: Arc<Mutex<u32>>,
    /// Indicates the type of measurement currently active
    m_type: Arc<Mutex<Option<MeasurementType>>>,
    /// Optional static mapping of hostnames to worker IDs
    worker_config: Option<HashMap<String, u32>>,
    /// Stacks of tasks coupled to workers, used for follow-up probes
    worker_stacks: Arc<Mutex<HashMap<u32, VecDeque<Task>>>>,
    /// Traceroute Configuration
    trace_config: Arc<RwLock<Option<TracerouteConfig>>>,
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
    /// A tuple containing: the worker ID and a boolean indicating if this is a reconnection of a closed worker.
    ///
    /// # Errors
    /// Returns an error if the hostname already exists and is used by a connected worker.
    fn get_worker_id(&self, hostname: &str) -> Result<(u32, bool), Box<Status>> {
        {
            let workers = self.saved_workers.lock().unwrap();
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
    let addr: SocketAddr = format!("[::]:{port}").parse()?;

    // Get optional configuration file
    let (current_worker_id, worker_config) = args
        .get_one::<String>("config")
        .map(load_worker_config)
        .unwrap_or_else(|| (Arc::new(Mutex::new(1)), None));

    let controller = ControllerService {
        saved_workers: Arc::new(Mutex::new(Vec::new())),
        cli_sender: Arc::new(Mutex::new(None)),
        ongoing_measurement: Arc::new(RwLock::new(None)),
        unique_id: current_worker_id,
        m_type: Arc::new(Mutex::new(None)),
        worker_config,
        worker_stacks: Arc::new(Mutex::new(HashMap::new())),
        trace_config: Arc::new(RwLock::new(None)),
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

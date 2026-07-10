mod cli;
mod config;
mod result_handler;
mod service;
mod task_distributor;
mod trace;
mod worker;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::ops::AddAssign;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::custom_module;
use crate::custom_module::manycastr::{Address, MeasurementType, Start, WorkerStatus};
use crate::orchestrator::config::{load_tls, load_worker_config};
use crate::orchestrator::mpsc::Sender;
use crate::orchestrator::result_handler::SessionTracker;
use crate::orchestrator::worker::WorkerSender;
use clap::ArgMatches;
use custom_module::manycastr::{
    Instruction, ReplyBatch, Task, controller_server::ControllerServer,
};
use log::{info, warn};
use tokio::sync::mpsc;
use tonic::codec::CompressionEncoding;
use tonic::transport::ServerTlsConfig;
use tonic::{Status, transport::Server};

type ResultMessage = Result<ReplyBatch, Status>;
type CliSender = Sender<ResultMessage>;
pub(crate) type CliHandle = Arc<Mutex<Option<CliSender>>>;

type TaskMessage = Result<Instruction, Status>;

/// Shared registry of connected worker senders. Updated when a worker reconnects.
pub(crate) type WorkerRegistry = Arc<Mutex<Vec<WorkerSender<TaskMessage>>>>;

/// Shared handle to the active measurement state. `None` when no measurement is running.
pub type MeasurementHandle = Arc<RwLock<Option<MeasurementState>>>;

/// A worker participating in the active measurement.
/// Participants can re-join after disconnect.
///
/// The entry is removed when the worker finishes.
#[derive(Debug)]
pub struct Participant {
    /// The worker's role in the measurement (Probing or Listening)
    pub role: WorkerStatus,
    /// When true, the Orchestrator waits for this participant before measurement finish.
    pub is_counted: bool,
}

/// All state associated with a single active measurement.
#[derive(Debug)]
pub struct MeasurementState {
    /// The measurement ID (used to filter on replies for the current measurement)
    pub m_id: u32,
    /// Worker IDs of connected Workers that are actively probing
    pub probing_workers: Vec<u32>,
    /// Participating workers (removed when a worker finishes; kept on disconnect for rejoin)
    pub participants: HashMap<u32, Participant>,
    /// Per-worker Start instructions (re-sent when a worker rejoins mid-measurement)
    pub start_instructions: HashMap<u32, Start>,
    /// Whether the current measurement is being finalized (no new tasks being sent)
    pub is_finalizing: bool,
    /// The measurement type (LACeS, catchment, latency, …)
    pub m_type: MeasurementType,
    /// Whether targets are checked for responsiveness before measurement probes (--responsive/--any)
    pub is_responsive: bool,
    /// Whether unresolved targets are retried origin by origin (--any)
    pub is_any: bool,
    /// Number of times each measurement probe is sent (always >= 1)
    pub nprobes: u32,
    /// Per-worker stacks of follow-up tasks (discovery → measurement, traceroute hops)
    pub worker_stacks: HashMap<u32, VecDeque<Task>>,
    /// Traceroute configuration and session tracker (None for non-traceroute measurements)
    pub trace_config: Option<TracerouteConfig>,
    /// Targets that responded to discovery (deduplicates follow-up tasks; --any uses it to skip resolved targets)
    pub resolved_targets: HashSet<Address>,
    /// Live feed state (None for hitlist-based measurements)
    pub live: Option<LiveState>,
}

impl MeasurementState {
    /// Number of connected workers participating in a measurement.
    /// The measurement is complete when this reaches zero.
    pub fn active_workers(&self) -> usize {
        self.participants.values().filter(|p| p.is_counted).count()
    }
}

/// Encode nprobes 1 as 0 for gRPC compression
#[inline]
pub fn wire_nprobes(nprobes: u32) -> u32 {
    if nprobes > 1 { nprobes } else { 0 }
}

/// Timeout for live-feed discovery probes
pub const LIVE_DISCOVERY_TIMEOUT_SECS: u64 = 3;

/// Worker selection of a live-feed target (parsed from `LiveTarget.worker_ids`).
#[derive(Debug)]
pub enum WorkerSel {
    /// Any single worker (round-robin over probing workers)
    Any,
    /// All probing workers (staggered broadcast)
    All,
    /// An explicit set of workers, staggered like a broadcast (sorted and deduplicated)
    Set(Vec<u32>),
}

impl WorkerSel {
    /// Whether the selection targets more than one worker.
    pub fn is_multi(&self) -> bool {
        match self {
            WorkerSel::Any => false,
            WorkerSel::All => true,
            WorkerSel::Set(ids) => ids.len() > 1,
        }
    }
}

/// State for a live (feed-based) measurement.
#[derive(Debug)]
pub struct LiveState {
    /// In-flight discovery targets awaiting a response
    pub pending: HashMap<Address, PendingTarget>,
    /// IPv4 origin IDs in configuration order (the order in which `origin:any` tries origins)
    pub origin_ids_v4: Vec<u32>,
    /// IPv6 origin IDs in configuration order (the order in which `origin:any` tries origins)
    pub origin_ids_v6: Vec<u32>,
    /// Follow-up task stacks for explicit worker sets (sent staggered like a broadcast)
    pub set_stacks: HashMap<Vec<u32>, VecDeque<Task>>,
    /// Recently dispatched trace targets and their reply deadline (feed-trace only).
    pub trace_targets: HashMap<Address, Instant>,
}

impl LiveState {
    /// The `origin:any` candidate origins for a target of the given IP version.
    pub fn origin_ids_for(&self, is_v6: bool) -> &[u32] {
        if is_v6 {
            &self.origin_ids_v6
        } else {
            &self.origin_ids_v4
        }
    }
}

/// A live target awaiting a probe reply before it is resolved (or retried/given up).
#[derive(Debug)]
pub struct PendingTarget {
    /// Worker selection for the follow-up measurement probes
    pub worker_sel: WorkerSel,
    /// Worker performing the task
    pub discovery_worker: u32,
    /// Next origin index to try on timeout for `origin:any` (None for `--responsive`)
    pub next_origin_idx: Option<usize>,
    /// Whether the probe sent is itself the measurement (single-worker `origin:any`)
    pub probe_is_measurement: bool,
    /// Number of measurement probes to send (per worker) once the target resolves (always >= 1)
    pub nprobes: u32,
    /// When the current attempt expires
    pub deadline: Instant,
}

/// Traceroute configuration
#[derive(Debug)]
pub struct TracerouteConfig {
    /// Session tracker for Trace Tasks
    pub session_tracker: SessionTracker,
    /// Timeout value for traceroute measurements (default 3s)
    pub timeout: u64,
    /// Max hop count for traceroute measurements (default 25)
    pub max_hops: u32,
    /// Hop count to start traceroute measurements with (default 4)
    pub initial_hop: u32,
    /// Maximum number of unresponsive hops before terminating the traceroute
    /// (default 5; tracemap confirmation window: 3)
    pub max_failures: u32,
    /// Whether to emit a '*' hop (no reply) to the CLI when a hop times out
    pub star_unresponsive: bool,
}

/// The main orchestrator service struct.
#[derive(Debug)]
pub struct ControllerService {
    /// List of connected workers
    saved_workers: WorkerRegistry,
    /// Sender to the CLI for streaming results
    cli_sender: CliHandle,
    /// All per-measurement state. `None` when idle.
    measurement: MeasurementHandle,
    /// Last used unique worker ID
    unique_id: Arc<Mutex<u32>>,
    /// Optional static mapping of hostnames to worker IDs
    worker_config: Option<HashMap<String, u32>>,
    /// Maximum probing rate (probes per second, per worker) enforced for live (feed-based) measurements
    live_rate: u32,
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
    /// * `hostname` - the hostname of the worker
    ///
    /// # Returns
    /// A tuple containing: the worker ID and a boolean indicating if this is a reconnection of a closed worker.
    ///
    /// # Errors
    /// Returns an error if the hostname already exists and is used by a connected worker.
    fn get_worker_id(&self, hostname: &str) -> Result<(u32, bool), Status> {
        {
            let workers = self.saved_workers.lock().unwrap();
            // Check if the hostname already exists in the workers list
            if let Some(existing_worker) = workers.iter().find(|w| w.hostname == hostname) {
                return if !existing_worker.is_closed() {
                    warn!("[Orchestrator] Refusing worker, hostname already exists: {hostname}");
                    Err(Status::already_exists("This hostname already exists"))
                } else {
                    // This is a reconnection of a closed worker.
                    let id = existing_worker.worker_id;
                    Ok((id, true))
                };
            }
        }

        // Check for a statically configured ID
        if let Some(worker_config) = &self.worker_config
            && let Some(worker_id) = worker_config.get(hostname)
        {
            return Ok((*worker_id, false));
        }

        // Return a new unique ID
        let new_id = self.get_unique_id();
        Ok((new_id, false))
    }
}

/// Starts the orchestrator on the specified port.
///
/// # Arguments
/// * `args` - the parsed command-line arguments
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
        measurement: Arc::new(RwLock::new(None)),
        unique_id: current_worker_id,
        worker_config,
        live_rate: *args.get_one::<u32>("live_rate").unwrap(),
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

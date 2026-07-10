use crate::ALL_ORIGINS;
use crate::custom_module;
use crate::custom_module::manycastr::controller_client::ControllerClient;
use crate::custom_module::manycastr::instruction::InstructionType;
use crate::custom_module::manycastr::{Address, End, Start, Task, Tasks};
use crate::worker::config::Worker;
use local_ip_address::{local_ip, local_ipv6};
use log::{info, warn};
use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tonic::Request;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};

/// Grace period after the last probe is sent before closing the listener
const END_REPLY_GRACE_SECS: u64 = 1;

impl Worker {
    /// Connect to the orchestrator.
    ///
    /// # Arguments
    /// * `address` - the address of the orchestrator in string format, containing both the IPv4 address and port number
    /// * `fqdn` - an optional string that contains the FQDN of the orchestrator certificate (if TLS is enabled)
    ///
    /// # Returns
    /// A gRPC client that is connected to the orchestrator
    ///
    /// # Remarks
    /// When `fqdn` is set, the connection is made over TLS and the orchestrator is
    /// authenticated against the CA certificate at `./tls/orchestrator.crt`
    pub(crate) async fn connect(
        address: String,
        fqdn: Option<&str>,
    ) -> Result<ControllerClient<Channel>, Box<dyn Error>> {
        let scheme = if fqdn.is_some() { "https" } else { "http" };
        let uri = format!("{scheme}://{address}");
        let mut endpoint = Channel::from_shared(uri)?;

        if let Some(domain_name) = fqdn {
            let cert_path = "tls/orchestrator.crt";
            let pem = std::fs::read_to_string(cert_path)
                .map_err(|e| format!("Failed to read CA cert at {cert_path}: {e}"))?;

            let ca = Certificate::from_pem(pem);
            let tls = ClientTlsConfig::new()
                .ca_certificate(ca)
                .domain_name(domain_name);

            endpoint = endpoint.tls_config(tls)?;
        }

        let channel = endpoint
            .keep_alive_timeout(Duration::from_secs(30))
            .http2_keep_alive_interval(Duration::from_secs(15))
            .tcp_keepalive(Some(Duration::from_secs(60)))
            .connect()
            .await?;

        Ok(ControllerClient::new(channel))
    }

    /// Establish a formal connection with the orchestrator.
    /// Obtains a unique worker ID from the orchestrator, establishes a stream for receiving tasks, and handles tasks as they come in.
    pub(crate) async fn connect_to_server(&mut self) -> Result<(), Box<dyn Error>> {
        let mut abort_outbound: Arc<AtomicBool> = Arc::new(AtomicBool::new(false)); // To force close outbound sending thread
        let worker_req = custom_module::manycastr::Worker {
            hostname: self.hostname.clone(),
            worker_id: 0,
            status: custom_module::manycastr::WorkerStatus::Idle as i32, // Placeholder status
            unicast_v6: local_ipv6().ok().map(Address::from),
            unicast_v4: local_ip().ok().map(Address::from),
        };

        // Establish stream of measurement instructions to the Orchestrator
        let mut stream = self
            .grpc_client
            .worker_connect(Request::new(worker_req))
            .await?
            .into_inner();

        // Obtain the unique worker ID set by the Orchestrator (first message)
        let init_msg = stream
            .message()
            .await?
            .ok_or("Stream closed before Init message received")?;

        let worker_id = match init_msg.instruction_type {
            Some(InstructionType::Init(init)) => init.worker_id as u16,
            _ => return Err("Did not receive Init message from orchestrator".into()),
        };
        info!("[Worker] Connected to Orchestrator with assigned worker ID: {worker_id}");

        // Await instructions
        let mut probe_interval: u64 = 1;
        while let Some(instruction) = stream.message().await? {
            let instr_type = match instruction.instruction_type {
                Some(it) => it,
                None => {
                    warn!("[Worker] Received empty instruction, skipping");
                    continue;
                }
            };

            // Check if we are currently busy with a measurement
            let is_busy = self.is_busy.load(Ordering::SeqCst);

            match (is_busy, instr_type) {
                // Starting a measurement (whilst idle)
                (false, InstructionType::Start(start)) => {
                    abort_outbound = Arc::new(AtomicBool::new(false));
                    probe_interval = start.probe_interval as u64;
                    self.handle_start_instruction(start, worker_id, abort_outbound.clone())?;
                }

                // Ending a measurement (whilst busy)
                (true, InstructionType::End(data)) => {
                    self.handle_end_instruction(data, abort_outbound.clone())
                        .await?;
                }

                // Receiving a new measurement (whilst busy) [INVALID]
                (true, InstructionType::Start(_)) => {
                    warn!("[Worker] Received new measurement while busy; ignoring.");
                }

                // Receiving a task batch (whilst busy): route tasks to the sender(s) of their origin
                (true, InstructionType::Tasks(task_batch)) => {
                    // Tasks with nprobes > 1 are re-sent every probe_interval seconds
                    let mut repeats: Vec<Task> = task_batch
                        .tasks
                        .iter()
                        .filter(|task| task.nprobes > 1)
                        .copied()
                        .collect();

                    // Send the tasks to the appropriate origins
                    route_tasks(&self.outbound_txs, task_batch).await;

                    if !repeats.is_empty() {
                        // Schedule the remaining sends for multi-probe tasks
                        repeats.sort_unstable_by_key(|task| task.nprobes);
                        schedule_repeats(self.outbound_txs.clone(), repeats, probe_interval);
                    }
                }

                // Receiving any other instruction (whilst busy) [INVALID]
                (true, _) => {
                    warn!("[Worker] Received unexpected instruction while busy; ignoring.");
                }

                // Receiving anything but a new measurement (whilst idle) [INVALID]
                (false, _) => {
                    warn!("[Worker] Received task data while idle; ignoring.");
                }
            }
        }
        info!("[Worker] Stream closed by Orchestrator");
        // TODO in-process reconnect

        Ok(())
    }

    /// Start a new measurement.
    /// Marks the worker as busy,
    /// Initializes the abort signals to False (for outbound and inbound threads)
    /// Calls the function to initialize the measurement
    ///
    /// # Arguments
    /// `start` - The definition of the new measurement
    /// `worker_id` - ID of this worker
    /// `abort_outbound` - Abort signal to forcefully close the outbound thread
    fn handle_start_instruction(
        &mut self,
        start: Start,
        worker_id: u16,
        abort_outbound: Arc<AtomicBool>,
    ) -> Result<(), Box<dyn Error>> {
        info!("[Worker] Starting measurement {}", start.m_id);

        // Mark busy and reset the abort signal
        self.is_busy.store(true, Ordering::SeqCst);
        self.abort_inbound.store(false, Ordering::SeqCst);

        // Initialize the measurement threads
        self.init(start, worker_id, abort_outbound)?;
        Ok(())
    }

    /// End an ongoing measurement.
    ///
    /// Graceful end (code 0): the outbound threads first drain any tasks still queued in their
    /// channels, then the inbound listener stays open for a grace period to capture in-flight
    /// replies before it is closed.
    /// Forceful end (code != 0): outbound and inbound threads are closed immediately,
    /// discarding any queued tasks.
    ///
    /// # Arguments
    /// `end_instruction` - End instruction sent by the Orchestrator with an ending code
    /// `abort_outbound` - Shared boolean to forcefully close the outbound/sending thread
    async fn handle_end_instruction(
        &mut self,
        end_instruction: End,
        abort_outbound: Arc<AtomicBool>,
    ) -> Result<(), Box<dyn Error>> {
        let is_graceful = end_instruction.code == 0;

        if is_graceful {
            info!("[Worker] Received finish signal");
        } else {
            warn!(
                "[Worker] Received abort signal (code {})",
                end_instruction.code
            );
            // Close inbound and outbound threads immediately (discard tasks left in the channel)
            self.abort_inbound.store(true, Ordering::SeqCst);
            abort_outbound.store(true, Ordering::SeqCst);
        }

        // Close outbound sending threads (gracefully); the End instruction is queued last
        let txs = std::mem::take(&mut self.outbound_txs);
        for (_, tx) in txs {
            let _ = tx.send(InstructionType::End(end_instruction)).await;
        }

        let handles = std::mem::take(&mut self.outbound_handles);
        if is_graceful {
            // Close the listener only after all outbound threads have sent their tasks
            let abort_inbound = self.abort_inbound.clone();
            tokio::task::spawn_blocking(move || {
                for handle in handles {
                    let _ = handle.join();
                }
                std::thread::sleep(Duration::from_secs(END_REPLY_GRACE_SECS));
                abort_inbound.store(true, Ordering::SeqCst);
            });
        }

        Ok(())
    }
}

/// Route a task batch to the outbound sender(s) of each task's origin.
async fn route_tasks(outbound_txs: &[(u32, Sender<InstructionType>)], task_batch: Tasks) {
    if let [(_, tx)] = outbound_txs {
        // Simple forward when there is only a single origin
        let _ = tx.send(InstructionType::Tasks(task_batch)).await;
    } else {
        // Forward when there is a matching origin_id attached, or ALL_ORIGINS is specified
        for (origin_id, tx) in outbound_txs {
            let tasks: Vec<Task> = task_batch
                .tasks
                .iter()
                .filter(|t| t.origin_id == *origin_id || t.origin_id == ALL_ORIGINS)
                .cloned()
                .collect();
            if !tasks.is_empty() {
                let _ = tx.send(InstructionType::Tasks(Tasks { tasks })).await;
            }
        }
    }
}

/// Re-send `repeats` every `probe_interval` seconds until every task has been
/// sent `nprobes` times, spacing out the repeated probes.
/// Stops early when the measurement ends (all outbound channels closed).
fn schedule_repeats(
    outbound_txs: Vec<(u32, Sender<InstructionType>)>,
    mut repeats: Vec<Task>,
    probe_interval: u64,
) {
    tokio::spawn(async move {
        for round in 1u32.. {
            tokio::time::sleep(Duration::from_secs(probe_interval)).await;
            // Remove all finished multi-probe tasks (assumes a list sorted by nprobes)
            repeats.drain(..repeats.partition_point(|task| task.nprobes <= round));
            if repeats.is_empty() || outbound_txs.iter().all(|(_, tx)| tx.is_closed()) {
                break; // All sends done, or the measurement ended
            }
            let tasks = repeats.clone();
            route_tasks(&outbound_txs, Tasks { tasks }).await;
        }
    });
}

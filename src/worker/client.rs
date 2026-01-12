use crate::custom_module;
use crate::custom_module::manycastr::controller_client::ControllerClient;
use crate::custom_module::manycastr::instruction::InstructionType;
use crate::custom_module::manycastr::{Address, End, Instruction};
use crate::worker::config::Worker;
use local_ip_address::{local_ip, local_ipv6};
use log::{info, warn};
use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use tonic::Request;

impl Worker {
    /// Connect to the orchestrator.
    ///
    /// # Arguments
    /// * `address` - the address of the orchestrator in string format, containing both the IPv4 address and port number
    /// * `fqdn` - an optional string that contains the FQDN of the orchestrator certificate (if TLS is enabled)
    pub(crate) async fn connect(
        address: String,
        fqdn: Option<&str>,
    ) -> Result<ControllerClient<Channel>, Box<dyn Error>> {
        let scheme = if fqdn.is_some() { "https" } else { "http" };
        let uri = format!("{}://{}", scheme, address);
        let mut endpoint = Channel::from_shared(uri)?;

        if let Some(domain_name) = fqdn {
            let cert_path = "tls/orchestrator.crt";
            let pem = std::fs::read_to_string(cert_path)
                .map_err(|e| format!("Failed to read CA cert at {}: {}", cert_path, e))?;

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
            status: "".to_string(),
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
        while let Some(instruction) = stream.message().await? {
            let instr_type = match instruction.instruction_type {
                Some(it) => it,
                None => {
                    warn!("[Worker] Received empty instruction, skipping");
                    continue;
                }
            };

            // Check if we are currently busy with a measurement
            let active_m_id = *self
                .current_m_id
                .lock()
                .map_err(|_| "Unable to obtain m_id mutex")?;

            match (active_m_id, instr_type) {
                // Starting a measurement (whilst idle)
                (None, InstructionType::Start(start)) => {
                    abort_outbound = Arc::new(AtomicBool::new(false));
                    self.handle_start_instruction(
                        Instruction {
                            instruction_type: Some(InstructionType::Start(start)),
                        },
                        worker_id,
                        abort_outbound.clone(),
                    )
                    .await?;
                }

                // Ending a measurement (whilst busy)
                (Some(_), InstructionType::End(data)) => {
                    self.handle_end_instruction(data, abort_outbound.clone())
                        .await?;
                }

                // Receiving a new measurement (whilst busy) [INVALID]
                (Some(_), InstructionType::Start(_)) => {
                    warn!("[Worker] Received new measurement while busy; ignoring.");
                }

                // Receiving a task (whilst busy)
                (Some(_), task_data) => {
                    for tx in &self.outbound_txs {
                        let _ = tx.send(task_data.clone()).await; // TODO can it be a reference to the task data? so we avoid the clone?
                    }
                }

                // Receiving anything but a new measurement (whilst idle) [INVALID]
                (None, _) => {
                    warn!("[Worker] Received task data while idle; ignoring.");
                }
            }
        }
        info!("[Worker] Stream closed by Orchestrator");

        Ok(())
    }

    /// Start a new measurement.
    /// Sets the Orchestrator assigned measurement ID,
    /// Initializes the abort signals to False (for outbound and inbound threads)
    /// Calls the function to initialize the measurement
    ///
    /// # Arguments
    /// `instr` - The instruction containing the Start instruction type
    /// `worker_id` - ID of this worker
    /// `abort_outbound` - Abort signal to forcefully close the outbound thread
    async fn handle_start_instruction(
        &mut self,
        instr: Instruction,
        worker_id: u16,
        abort_outbound: Arc<AtomicBool>,
    ) -> Result<(), Box<dyn Error>> {
        let start_data = match instr.instruction_type.as_ref().unwrap() {
            InstructionType::Start(s) => s,
            _ => unreachable!(),
        };

        info!("[Worker] Starting measurement {}", start_data.m_id);

        // Set the measurement ID and abort signal
        *self.current_m_id.lock().unwrap() = Some(start_data.m_id);
        self.abort_inbound.store(false, Ordering::SeqCst);

        // Initialize the measurement threads
        self.init(instr, worker_id, abort_outbound)?;
        Ok(())
    }

    /// End an ongoing measurement.
    /// Closes listening thread gracefully.
    /// Closes sending thread forcefully or gracefully (depending on end code)
    ///
    /// # Arguments
    /// `end_instruction` - End instruction sent by the Orchestrator with an ending code
    /// `abort_outbound` - Shared boolean to forcefully close the outbound/sending thread
    async fn handle_end_instruction(
        &mut self,
        end_instruction: End,
        abort_outbound: Arc<AtomicBool>,
    ) -> Result<(), Box<dyn Error>> {
        // Close inbound listening thread (gracefully)
        self.abort_inbound.store(true, Ordering::SeqCst);

        if end_instruction.code == 0 {
            info!("[Worker] Received finish signal");
        } else {
            warn!(
                "[Worker] Received abort signal (code {})",
                end_instruction.code
            );
            // Close outbound thread forcefully (force stop without parsing tasks in the channel)
            abort_outbound.store(true, Ordering::SeqCst);
        }

        // Close outbound sending threads (gracefully)
        let txs = std::mem::take(&mut self.outbound_txs);

        for tx in txs {
            let _ = tx.send(InstructionType::End(end_instruction.clone())).await;
        }

        Ok(())
    }
}

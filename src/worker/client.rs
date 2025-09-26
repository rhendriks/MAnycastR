use crate::custom_module;
use crate::custom_module::manycastr::controller_client::ControllerClient;
use crate::custom_module::manycastr::instruction::InstructionType;
use crate::custom_module::manycastr::{Address, End, Finished, TaskResult};
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
    ///
    /// * 'address' - the address of the orchestrator in string format, containing both the IPv4 address and port number
    ///
    /// * 'fqdn' - an optional string that contains the FQDN of the orchestrator certificate (if TLS is enabled)
    ///
    /// # Example
    ///
    /// ```
    /// let client = connect("127.0.0.0:50001", true);
    /// ```
    pub(crate) async fn connect(
        address: String,
        fqdn: Option<&String>,
    ) -> Result<ControllerClient<Channel>, Box<dyn Error>> {
        let channel = if let Some(fqdn) = fqdn {
            // Secure connection
            let addr = format!("https://{address}");

            // Load the CA certificate used to authenticate the orchestrator
            let pem = std::fs::read_to_string("tls/orchestrator.crt")
                .expect("Unable to read CA certificate at ./tls/orchestrator.crt");
            let ca = Certificate::from_pem(pem);
            // Create a TLS configuration
            let tls = ClientTlsConfig::new().ca_certificate(ca).domain_name(fqdn);

            let builder = Channel::from_shared(addr.to_owned()).expect("Unable to set address"); // Use the address provided
            builder
                .keep_alive_timeout(Duration::from_secs(30))
                .http2_keep_alive_interval(Duration::from_secs(15))
                .tcp_keepalive(Some(Duration::from_secs(60)))
                .tls_config(tls)
                .expect("Unable to set TLS configuration")
                .connect()
                .await
                .expect("Unable to connect to orchestrator")
        } else {
            // Unsecure connection
            let addr = format!("http://{address}");

            Channel::from_shared(addr.to_owned())
                .expect("Unable to set address")
                .keep_alive_timeout(Duration::from_secs(30))
                .http2_keep_alive_interval(Duration::from_secs(15))
                .tcp_keepalive(Some(Duration::from_secs(60)))
                .connect()
                .await
                .expect("Unable to connect to orchestrator")
        };
        // Create worker with secret token that is used to authenticate worker commands.
        let client = ControllerClient::new(channel);

        Ok(client)
    }

    /// Establish a formal connection with the orchestrator.
    ///
    /// Obtains a unique worker ID from the orchestrator, establishes a stream for receiving tasks, and handles tasks as they come in.
    pub(crate) async fn connect_to_server(&mut self) -> Result<(), Box<dyn Error>> {
        info!("[Worker] Connecting to orchestrator");
        let mut abort_s: Option<Arc<AtomicBool>> = None;

        // Get the local unicast addresses
        let unicast_v6 = local_ipv6().ok().map(Address::from);
        let unicast_v4 = local_ip().ok().map(Address::from);

        let worker = custom_module::manycastr::Worker {
            hostname: self.hostname.clone(),
            worker_id: 0, // This will be set after the connection
            status: "".to_string(),
            unicast_v6,
            unicast_v4,
        };

        // Connect to the orchestrator
        let response = self
            .grpc_client
            .worker_connect(Request::new(worker))
            .await
            .expect("Unable to connect to orchestrator");

        let mut stream = response.into_inner();
        // Read the assigned unique worker ID
        let id_message = stream
            .message()
            .await
            .expect("Unable to await stream")
            .expect("Unable to receive worker ID");
        let worker_id = if let Some(InstructionType::Init(init)) = id_message.instruction_type {
            init.worker_id as u16
        } else {
            panic!("Did not receive Init message from orchestrator");
        };
        info!("[Worker] Connected to the orchestrator with worker_id: {worker_id}");

        // Await tasks
        while let Some(instruction) = stream.message().await.expect("Unable to receive task") {
            // If we already have an active measurement
            if self.current_m_id.lock().unwrap().is_some() {
                // If the CLI disconnected we will receive this message
                match instruction.instruction_type {
                    None => {
                        warn!("[Worker] Received empty task, skipping");
                        continue;
                    }
                    Some(InstructionType::Start(_)) => {
                        warn!("[Worker] Received new measurement during an active measurement, skipping");
                        continue;
                    }
                    Some(InstructionType::End(data)) => {
                        // Received finish signal
                        if data.code == 0 {
                            info!(
                                "[Worker] Received measurement finished signal from orchestrator"
                            );
                            // Close inbound threads
                            self.abort_s.store(true, Ordering::SeqCst);
                            // Close outbound threads gracefully
                            if let Some(tx) = self.outbound_tx.take() {
                                tx.send(InstructionType::End(End { code: 0 })).await.expect(
                                    "Unable to send measurement_finished to outbound thread",
                                );
                            }
                        } else if data.code == 1 {
                            info!("[Worker] CLI disconnected, aborting measurement");

                            // Close the inbound threads
                            self.abort_s.store(true, Ordering::SeqCst);
                            // finish will be None if this worker is not probing
                            if let Some(abort_s) = &abort_s {
                                // Close outbound threads
                                abort_s.store(true, Ordering::SeqCst);
                            }
                        } else {
                            warn!("[Worker] Received invalid code from orchestrator");
                            continue;
                        }
                    }
                    Some(task) => {
                        // outbound_tx will be None if this worker is not probing
                        if let Some(outbound_tx) = &self.outbound_tx {
                            // Send the task to the prober
                            outbound_tx
                                .send(task)
                                .await
                                .expect("Unable to send task to outbound thread");
                        }
                    }
                };

                // If we don't have an active measurement
            } else {
                let (is_probing, m_id) = match instruction.instruction_type.clone() {
                    Some(InstructionType::Start(start)) => {
                        (!start.tx_origins.is_empty(), start.m_id)
                    }
                    _ => {
                        // First task is not a start measurement task
                        continue;
                    }
                };

                info!("[Worker] Starting new measurement");
                *self.current_m_id.lock().unwrap() = Some(m_id);
                self.abort_s.store(false, Ordering::SeqCst);

                if is_probing {
                    // This worker is probing
                    // Initialize signal finish atomic boolean
                    abort_s = Some(Arc::new(AtomicBool::new(false)));

                    self.init(instruction, worker_id, abort_s.clone());
                } else {
                    // This worker is not probing
                    abort_s = None;
                    self.outbound_tx = None;
                    self.init(instruction, worker_id, None);
                }
            }
        }
        info!("[Worker] Stopped awaiting tasks");

        Ok(())
    }

    /// Send a TaskResult to the orchestrator
    pub(crate) async fn send_result_to_server(
        &mut self,
        task_result: TaskResult,
    ) -> Result<(), Box<dyn Error>> {
        self.grpc_client
            .send_result(Request::new(task_result))
            .await?;

        Ok(())
    }

    /// Let the orchestrator know the current measurement is finished.
    ///
    /// When a measurement is finished the orchestrator knows not to expect any more results from this worker.
    ///
    /// # Arguments
    ///
    /// * 'finished' - the 'Finished' message to send to the orchestrator
    pub(crate) async fn measurement_finish_to_server(
        &mut self,
        finished: Finished,
    ) -> Result<(), Box<dyn Error>> {
        info!("[Worker] Letting the orchestrator know that this worker finished the measurement");
        self.current_m_id.lock().unwrap().take(); // Set current measurement ID to None
        self.grpc_client
            .measurement_finished(Request::new(finished))
            .await?;

        Ok(())
    }
}

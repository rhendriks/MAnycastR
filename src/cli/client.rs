use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use chrono::Local;
use indicatif::{ProgressBar, ProgressStyle};
use log::{error, info, warn};
use tokio::sync::mpsc::unbounded_channel;
use tonic::Request;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use crate::cli::commands::start::MeasurementExecutionArgs;
use crate::custom_module::manycastr::controller_client::ControllerClient;
use crate::custom_module::manycastr::{ScheduleMeasurement, TaskResult};
use crate::{A_ID, CHAOS_ID, ICMP_ID, TCP_ID};
use crate::cli::writer::{write_results, write_results_parquet, MetadataArgs, WriteConfig};
use crate::custom_module::Separated;

/// A CLI client that creates a connection with the 'orchestrator' and sends the desired commands based on the command-line input.
pub struct CliClient {
    pub(crate) grpc_client: ControllerClient<Channel>,
}

impl CliClient {
    /// Perform a measurement at the orchestrator, await measurement results, and write them to a file.
    ///
    /// # Arguments
    ///
    /// * 'm_definition' - measurement definition  for the orchestrator created from the command-line arguments
    ///
    /// * 'args' - contains additional arguments for the measurement execution
    ///
    /// * 'is_ipv6' - boolean whether the measurement is IPv6 or not
    ///
    /// * 'is_unicast' - boolean whether the measurement is unicast or anycast
    pub(crate) async fn do_measurement_to_server(
        &mut self,
        m_definition: ScheduleMeasurement,
        args: MeasurementExecutionArgs<'_>,
        is_ipv6: bool,
        is_unicast: bool,
    ) -> Result<(), Box<dyn Error>> {
        let is_divide = m_definition.is_divide;
        let probing_rate = m_definition.probing_rate;
        let worker_interval = m_definition.worker_interval;
        let m_type = m_definition.m_type;
        let is_latency = m_definition.is_latency;
        let is_responsive = m_definition.is_responsive;
        let origin_str =  if args.is_config { // TODO encode configs into configurations
            "Anycast configuration-based".to_string()
        } else {
            m_definition
                .configurations
                .first()
                .and_then(|conf| conf.origin.as_ref())
                .map(|origin| {
                    format!(
                        "Anycast (source IP: {}, source port: {}, destination port: {})",
                        origin.src.unwrap(),
                        origin.sport,
                        origin.dport
                    )
                })
                .expect("No anycast origin found")
        };

        // List of Worker IDs that are sending out probes (empty means all)
        let probing_workers: Vec<String> = if m_definition
            .configurations
            .iter()
            .any(|config| config.worker_id == u32::MAX)
        {
            Vec::new() // all workers are probing
        } else {
            // Get list of unique worker hostnames that are probing
            m_definition
                .configurations
                .iter()
                .map(|config| {
                    args.worker_map
                        .get_by_left(&config.worker_id)
                        .unwrap_or_else(|| {
                            panic!("Worker ID {} is not a connected worker!", config.worker_id)
                        })
                        .clone()
                })
                .collect::<HashSet<String>>() // Use HashSet to ensure uniqueness
                .into_iter()
                .collect::<Vec<String>>()
        };

        let number_of_probers = if probing_workers.is_empty() {
            args.worker_map.len() as f32
        } else {
            probing_workers.len() as f32
        };

        let m_time = if is_divide || is_latency {
            ((args.hitlist_length as f32 / (probing_rate as f32 * number_of_probers)) + 1.0) / 60.0
        } else {
            (((number_of_probers - 1.0) * worker_interval as f32) // Last worker starts probing
                + (args.hitlist_length as f32 / probing_rate as f32) // Time to probe all addresses
                + 1.0) // Time to wait for last replies
                / 60.0 // Convert to minutes
        };

        if is_divide {
            info!("[CLI] Divide-and-conquer enabled");
        }
        info!("[CLI] This measurement will take an estimated {m_time:.2} minutes");

        let response = self
            .grpc_client
            .do_measurement(Request::new(m_definition.clone()))
            .await;
        if let Err(e) = response {
            error!(
                "[CLI] Orchestrator did not perform the measurement for reason: '{}'",
                e.message()
            );
            return Err(Box::new(e));
        }
        let start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let timestamp_start = Local::now();
        let timestamp_start_str = timestamp_start.format("%Y-%m-%dT%H_%M_%S").to_string();
        info!(
            "[CLI] Measurement started at {}",
            timestamp_start.format("%H:%M:%S")
        );

        // Progress bar
        let total_steps = (m_time * 60.0) as u64; // measurement_length in seconds
        let pb = ProgressBar::new(total_steps);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
                .unwrap()
                .progress_chars("#>-"),
        );
        let is_done = Arc::new(AtomicBool::new(false));
        let is_done_clone = is_done.clone();

        // Spawn a separate async task to update the progress bar
        tokio::spawn(async move {
            // If we are streaming to the CLI, we cannot use a progress bar
            if !args.is_cli {
                for _ in 0..total_steps {
                    if is_done_clone.load(Ordering::Relaxed) {
                        break;
                    }
                    pb.inc(1); // Increment the progress bar by one step
                    tokio::time::sleep(Duration::from_secs(1)).await; // Simulate time taken for each step
                }
            }
        });

        let mut graceful = false; // Will be set to true if the stream closes gracefully
        // Obtain the Stream from the orchestrator and read from it
        let mut stream = response
            .expect("Unable to obtain the orchestrator stream")
            .into_inner();
        // Channel for writing results to file
        let (tx_r, rx_r) = unbounded_channel();

        // Get measurement type
        let type_str = match m_type as u8 {
            ICMP_ID => "ICMP",
            A_ID => "DNS",
            TCP_ID => "TCP",
            CHAOS_ID => "CHAOS",
            _ => "ICMP",
        };
        let type_str = if is_ipv6 {
            format!("{type_str}v6")
        } else {
            format!("{type_str}v4")
        };

        // Determine the type of measurement
        let filetype = if is_unicast { "LB_" } else { "AB_" }; // TODO filetype for both unicast and anycast
        // TODO filetype for traceroute measurements

        // Determine the file extension based on the output format
        let mut is_parquet = args.is_parquet;

        // Determine traceroute
        let is_traceroute = args.is_traceroute; // TODO change filename for traceroute measurements

        // traceroute only supported for ICMP
        if is_traceroute && m_type as u8 != ICMP_ID {
            panic!("Traceroute measurements are only supported for ICMP!");
        }

        let extension = if is_parquet { ".parquet" } else { ".csv.gz" };

        // Output file
        let file_path = if let Some(path) = args.out_path {
            if path.ends_with('/') {
                // User provided a path, use default naming convention for file
                format!("{path}{filetype}{type_str}{timestamp_start_str}{extension}")
            } else {
                // User provided a file (with possibly a path)

                if path.ends_with(".parquet") {
                    is_parquet = true; // If the file ends with .parquet, we will write in Parquet format
                }
                path.to_string()
            }
        } else {
            // Write file to current directory using default naming convention
            format!("./{filetype}{type_str}{timestamp_start_str}{extension}")
        };

        // Create the output file
        let file = File::create(file_path).expect("Unable to create file");

        let metadata_args = MetadataArgs {
            is_divide,
            origin_str,
            hitlist: args.hitlist_path,
            is_shuffle: args.is_shuffle,
            m_type_str: type_str,
            probing_rate,
            interval: worker_interval,
            active_workers: probing_workers,
            all_workers: &args.worker_map,
            configurations: &m_definition.configurations,
            is_config: args.is_config,
            is_latency,
            is_responsive,
        };

        let is_multi_origin = if is_unicast {
            false
        } else {
            // Check if any configuration has origin_id that is not 0 or u32::MAX
            m_definition.configurations.iter().any(|conf| {
                conf.origin
                    .as_ref()
                    .is_some_and(|origin| origin.origin_id != 0 && origin.origin_id != u32::MAX)
            })
        };

        let config = WriteConfig {
            print_to_cli: args.is_cli,
            output_file: file,
            metadata_args,
            m_type,
            is_multi_origin,
            is_symmetric: is_unicast || is_latency,
            worker_map: args.worker_map.clone(),
        };

        // Start thread that writes results to file
        if is_parquet {
            write_results_parquet(rx_r, config);
        } else {
            write_results(rx_r, config);
        }

        let mut replies_count = 0;
        'mloop: while let Some(task_result) = match stream.message().await {
            Ok(Some(result)) => Some(result),
            Ok(None) => {
                error!("[CLI] Stream closed by orchestrator");
                break 'mloop;
            } // Stream is exhausted
            Err(e) => {
                error!("[CLI] Error receiving message: {e}");
                break 'mloop;
            }
        } {
            // A default result notifies the CLI that it should not expect any more results
            if task_result == TaskResult::default() {
                tx_r.send(task_result).unwrap(); // Let the results channel know that we are done
                graceful = true;
                break;
            }

            replies_count += task_result.result_list.len();
            // Send the results to the file channel
            tx_r.send(task_result).unwrap();
        }

        is_done.store(true, Ordering::Relaxed); // Signal the progress bar to stop

        let end = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let length = (end - start) as f64 / 1_000_000_000.0; // Measurement length in seconds
        info!("[CLI] Waited {length:.6} seconds for results. Captured {} replies", replies_count.with_separator());

        // If the stream closed during a measurement
        if !graceful {
            tx_r.send(TaskResult::default()).unwrap(); // Let the results channel know that we are done
            warn!("[CLI] Measurement ended prematurely!");
        }

        tx_r.closed().await; // Wait for all results to be written to file

        Ok(())
    }

    /// Connect to the orchestrator
    ///
    /// # Arguments
    ///
    /// * 'address' - the address of the orchestrator (e.g., 10.10.10.10:50051)
    ///
    /// * 'fqdn' - an optional string that contains the FQDN of the orchestrator certificate (if TLS is enabled)
    ///
    /// # Returns
    ///
    /// A gRPC client that is connected to the orchestrator
    ///
    /// # Panics
    ///
    /// If the connection to the orchestrator fails
    ///
    /// # Remarks
    ///
    /// TLS enabled requires a certificate at ./tls/orchestrator.crt
    pub(crate) async fn connect(
        address: &str,
        fqdn: Option<&String>,
    ) -> Result<ControllerClient<Channel>, Box<dyn Error>> {
        let channel = if let Some(fqdn) = fqdn {
            // Secure connection
            let addr = format!("https://{address}");

            // Load the CA certificate used to authenticate the orchestrator
            let pem = fs::read_to_string("tls/orchestrator.crt")
                .expect("Unable to read CA certificate at ./tls/orchestrator.crt");
            let ca = Certificate::from_pem(pem);

            let tls = ClientTlsConfig::new().ca_certificate(ca).domain_name(fqdn);

            let builder = Channel::from_shared(addr.to_owned())?; // Use the address provided
            builder
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
                .connect()
                .await
                .expect("Unable to connect to orchestrator")
        };
        // Create client with secret token that is used to authenticate client commands.
        let client = ControllerClient::new(channel);

        Ok(client)
    }
}

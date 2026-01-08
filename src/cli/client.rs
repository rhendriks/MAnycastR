use crate::cli::commands::start::MeasurementExecutionArgs;
use crate::cli::writer::parquet_writer::write_results_parquet;
use crate::cli::writer::{write_results_csv, MetadataArgs, WriteConfig};
use crate::custom_module::manycastr::controller_client::ControllerClient;
use crate::custom_module::manycastr::{MeasurementType, ReplyBatch, ScheduleMeasurement};
use crate::custom_module::Separated;
use crate::ALL_WORKERS;
use chrono::Local;
use indicatif::{ProgressBar, ProgressStyle};
use log::{error, info, warn};
use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::unbounded_channel;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use tonic::Request;

/// A CLI client that creates a connection with the 'orchestrator' and sends the desired commands based on the command-line input.
pub struct CliClient {
    pub(crate) grpc_client: ControllerClient<Channel>,
}

impl CliClient {
    /// Perform a measurement at the orchestrator, await measurement results, and write them to a file.
    ///
    /// # Arguments
    /// * `m_def` - measurement definition  for the orchestrator created from the command-line arguments
    /// * `args` - contains additional arguments for the measurement execution
    /// * `is_ipv6` - boolean whether the measurement is IPv6 or not
    pub(crate) async fn do_measurement_to_server(
        &mut self,
        m_def: ScheduleMeasurement,
        args: MeasurementExecutionArgs<'_>,
        is_ipv6: bool,
        m_type: MeasurementType,
    ) -> Result<(), Box<dyn Error>> {
        let probing_rate = m_def.probing_rate;
        let worker_interval = m_def.worker_interval;
        let is_responsive = m_def.is_responsive;

        // Get number of probers
        let number_of_probers = {
            let worker_ids: HashSet<_> = m_def
                .configurations
                .iter()
                .map(|conf| conf.worker_id)
                .collect();

            if worker_ids.contains(&ALL_WORKERS) {
                args.worker_map.len()
            } else {
                worker_ids.len()
            }
        };

        let m_time = match m_def.m_type() {
            MeasurementType::Verfploeter | MeasurementType::AnycastLatency => {
                ((args.hitlist_length as f32 / (probing_rate as f32 * number_of_probers as f32))
                    + 1.0)
                    / 60.0
            }
            _ => {
                (((number_of_probers - 1) as f32 * worker_interval as f32) // Last worker starts probing
            + (args.hitlist_length as f32 / probing_rate as f32) // Time to probe all addresses
            + 1.0) // Time to wait for last replies
            / 60.0 // Convert to minutes
            }
        };

        info!("[CLI] Performing {} measurement", m_def.m_type);

        info!("[CLI] This measurement will take an estimated {m_time:.2} minutes");

        let response = self
            .grpc_client
            .do_measurement(Request::new(m_def.clone()))
            .await;
        if let Err(e) = response {
            error!(
                "[CLI] Orchestrator did not perform the measurement for reason: '{}'",
                e.message()
            );
            return Err(Box::new(e));
        }
        let start = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let timestamp_start_str = Local::now().format("%Y%m%d-%H%M%S").to_string();

        // Progress bar
        let total_steps = (m_time * 60.0) as u64; // measurement_length in seconds
        let pb = ProgressBar::new(total_steps);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )?
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

        // Get protocol and IP version
        let type_str = format!(
            "{}{}",
            m_def.p_type().as_str(),
            if is_ipv6 { "v6" } else { "v4" }
        );

        // Determine traceroute
        let is_record = args.is_record;
        // Determine the file extension based on the output format
        let mut is_parquet = args.is_parquet;

        let extension = if is_parquet { ".parquet" } else { ".csv.gz" };

        let path = args.out_path;
        // Output file
        let file_path = if path.ends_with('/') {
            // User provided a path, use default naming convention for file
            format!("{path}{m_type}-{type_str}-{timestamp_start_str}{extension}")
        } else {
            // User provided a file (with possibly a path)
            if path.ends_with(".parquet") {
                is_parquet = true; // If the file ends with .parquet, we will write in Parquet format
            }
            path
        };

        // Create the output file
        info!("[CLI] Writing results to {file_path}");
        let file = File::create(file_path).expect("Unable to create file");

        let metadata_args = MetadataArgs {
            hitlist: args.hitlist_path,
            is_shuffle: args.is_shuffle,
            m_type_str: type_str,
            probing_rate,
            interval: worker_interval,
            all_workers: &args.worker_map,
            configurations: &m_def.configurations,
            is_responsive,
            m_type: m_def.m_type(),
            p_type: m_def.p_type(),
        };

        // Check if any configuration has origin_id that is not 0 or u32::MAX -> multi origin
        let is_multi_origin = m_def.configurations.iter().any(|conf| {
            conf.origin
                .as_ref()
                .is_some_and(|origin| origin.origin_id != 0 && origin.origin_id != u32::MAX)
        });

        let config = WriteConfig {
            print_to_cli: args.is_cli,
            output_file: file,
            metadata_args,
            p_type: m_def.p_type(),
            m_type: m_def.m_type(),
            is_multi_origin,
            worker_map: args.worker_map.clone(),
            is_record,
        };

        // Start thread that writes results to file
        if is_parquet {
            write_results_parquet(rx_r, config);
        } else {
            write_results_csv(rx_r, config);
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
            if task_result == ReplyBatch::default() {
                tx_r.send(task_result)?; // Let the results channel know that we are done
                graceful = true;
                break;
            }

            replies_count += task_result.results.len();
            // Send the results to the file channel
            tx_r.send(task_result)?;
        }

        is_done.store(true, Ordering::Relaxed); // Signal the progress bar to stop

        let end = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let length = (end - start) as f32 / 60.0; // Measurement length in minutes
        info!(
            "[CLI] Waited {length:.2} minutes for results. Captured {} replies",
            replies_count.with_separator()
        );

        // If the stream closed during a measurement
        if !graceful {
            tx_r.send(ReplyBatch::default())?; // Let the results channel know that we are done
            warn!("[CLI] Measurement ended prematurely!");
        }

        tx_r.closed().await; // Wait for all results to be written to file

        Ok(())
    }

    /// Connect to the orchestrator
    ///
    /// # Arguments
    /// * `address` - the address of the orchestrator (e.g., 10.10.10.10:50051)
    /// * `fqdn` - an optional string that contains the FQDN of the orchestrator certificate (if TLS is enabled)
    ///
    /// # Returns
    /// A gRPC client that is connected to the orchestrator
    ///
    /// # Remarks
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

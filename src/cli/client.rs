use crate::cli::commands::start::MeasurementExecutionArgs;
use crate::cli::feed::{FEED_CHANNEL_SIZE, FeedStream, read_stdin_feed};
use crate::cli::writer::parquet_writer::write_results_parquet;
use crate::cli::writer::{MetadataArgs, WriteConfig, write_results_csv};
use crate::custom_module::manycastr::ProtocolType::ChaosDns;
use crate::custom_module::manycastr::controller_client::ControllerClient;
use crate::custom_module::manycastr::{
    CliMessage, MeasurementType, ReplyBatch, ScheduleMeasurement, cli_message,
};
use crate::custom_module::{Separated, has_anycast_origin};
use crate::{ALL_WORKERS, SINGLE_ORIGIN};
use chrono::Local;
use indicatif::{ProgressBar, ProgressStyle};
use log::{error, info, warn};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::{channel, unbounded_channel};
use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use tonic::{Request, Streaming};

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
    /// * `m_type` - Measurement type
    pub(crate) async fn do_measurement_to_server(
        &mut self,
        m_def: ScheduleMeasurement,
        args: MeasurementExecutionArgs<'_>,
        m_type: MeasurementType,
    ) -> Result<(), Box<dyn Error>> {
        let probing_rate = m_def.probing_rate;
        let worker_interval = m_def.worker_interval;

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

        // Latency anycast measurements divide the hitlist among workers
        let is_divided = match m_def.m_type() {
            MeasurementType::Catchment | MeasurementType::Tracemap => true,
            MeasurementType::AnycastLatency => has_anycast_origin(&m_def.configurations),
            _ => false,
        };

        let m_time = if is_divided {
            ((args.hitlist_length as f32 / (probing_rate as f32 * number_of_probers as f32)) + 5.0)
                / 60.0
        } else {
            ((number_of_probers.saturating_sub(1) as f32 * worker_interval as f32) // Last worker starts probing
            + (args.hitlist_length as f32 / probing_rate as f32) // Time to probe all addresses
            + 5.0) // Time to wait for last replies
            / 60.0 // Convert to minutes
        };

        info!("[CLI] Performing {} measurement", m_def.m_type());
        info!("[CLI] This measurement will take an estimated {m_time:.2} minutes");

        let response = self
            .grpc_client
            .do_measurement(Request::new(m_def.clone()))
            .await;
        if let Err(e) = response {
            error!(
                "[CLI] Orchestrator did not perform the measurement: '{}'",
                e.message()
            );
            return Err(Box::new(e));
        }
        // Obtain the Stream from the orchestrator and read from it
        let stream = response
            .expect("Unable to obtain the orchestrator stream")
            .into_inner();

        stream_results_to_file(stream, &m_def, args, m_type, Some(m_time)).await
    }

    /// Perform a live (feed-based) measurement at the orchestrator.
    ///
    /// Opens a bidirectional stream: the measurement definition is sent first, then
    /// NDJSON targets read from stdin are forwarded as they arrive. The measurement
    /// runs (possibly idle) until stdin reaches EOF or Ctrl+C is pressed, after which
    /// the feed is closed and the last results are awaited.
    ///
    /// # Arguments
    /// * `m_def` - measurement definition for the orchestrator (empty hitlist)
    /// * `args` - contains additional arguments for the measurement execution
    pub(crate) async fn do_live_measurement_to_server(
        &mut self,
        m_def: ScheduleMeasurement,
        args: MeasurementExecutionArgs<'_>,
    ) -> Result<(), Box<dyn Error>> {
        info!(
            "[CLI] Performing live {} measurement; reading NDJSON targets from stdin (e.g., {{\"dst\":\"1.1.1.1\"}})",
            m_def.m_type()
        );

        // Bounded channels: when the orchestrator (or its rate limit) cannot keep up, block stdin
        let (feed_tx, mut feed_rx) = channel::<CliMessage>(FEED_CHANNEL_SIZE);
        let (grpc_tx, grpc_rx) = channel::<CliMessage>(16);

        // The first message on the stream must be the measurement definition
        grpc_tx
            .send(CliMessage {
                message: Some(cli_message::Message::Start(m_def.clone())),
            })
            .await?;

        // Read NDJSON targets from stdin on a blocking thread
        let worker_map = args.worker_map.clone();
        // Origin ID -> IP version, to match feed targets with compatible origins
        let origins: HashMap<u32, bool> = m_def
            .configurations
            .iter()
            .filter_map(|conf| conf.origin)
            .map(|origin| (origin.origin_id, origin.src.is_some_and(|src| src.is_v6())))
            .collect();
        std::thread::spawn(move || read_stdin_feed(feed_tx, worker_map, origins));

        // Forward stdin targets to the gRPC stream until EOF or Ctrl+C.
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        info!("[CLI] Ctrl+C received, closing the live feed (awaiting last results; Ctrl+C again to force quit)");
                        tokio::spawn(async {
                            let _ = tokio::signal::ctrl_c().await;
                            std::process::exit(1);
                        });
                        break;
                    }
                    msg = feed_rx.recv() => match msg {
                        Some(msg) => {
                            if grpc_tx.send(msg).await.is_err() {
                                break; // Orchestrator closed the stream
                            }
                        }
                        None => {
                            info!("[CLI] Live feed reached EOF, awaiting last results");
                            break;
                        }
                    }
                }
            }
        });

        // Handle measurement replies
        let response = self
            .grpc_client
            .live_measurement(Request::new(FeedStream { inner: grpc_rx }))
            .await;
        if let Err(e) = response {
            error!(
                "[CLI] Orchestrator did not perform the live measurement: '{}'",
                e.message()
            );
            return Err(Box::new(e));
        }

        // Get stream of measurement replies and write to file
        let stream = response
            .expect("Unable to obtain the orchestrator stream")
            .into_inner();

        // Live results are written as LACeS rows TODO support separate live traceroute mode
        stream_results_to_file(stream, &m_def, args, MeasurementType::Laces, None).await
    }
}

/// Consume the orchestrator's result stream and write the replies to file.
///
/// Shared by hitlist-based and live measurements. A progress bar is shown only when
/// an estimated measurement duration is provided (live measurements are open-ended).
/// `row_m_type` selects the output row format (live measurements use LACeS rows);
/// the file name and metadata reflect the measurement definition's own type.
async fn stream_results_to_file(
    mut stream: Streaming<ReplyBatch>,
    m_def: &ScheduleMeasurement,
    args: MeasurementExecutionArgs<'_>,
    row_m_type: MeasurementType,
    m_time: Option<f32>,
) -> Result<(), Box<dyn Error>> {
    // Get start time of measurement
    let start = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let timestamp_start_str = Local::now().format("%Y%m%d-%H%M%S").to_string();

    let is_done = Arc::new(AtomicBool::new(false));
    // Progress bar (only when the measurement duration can be estimated)
    if let Some(m_time) = m_time {
        let total_steps = (m_time * 60.0) as u64; // measurement_length in seconds
        let pb = ProgressBar::new(total_steps);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )?
            .progress_chars("#>-"),
        );
        let is_done_clone = is_done.clone();
        let is_cli = args.is_cli;

        // Spawn a separate async task to update the progress bar
        tokio::spawn(async move {
            // If we are streaming to the CLI, we cannot use a progress bar
            if !is_cli {
                for _ in 0..total_steps {
                    if is_done_clone.load(Ordering::Relaxed) {
                        break;
                    }
                    pb.inc(1); // Increment the progress bar by one step
                    tokio::time::sleep(Duration::from_secs(1)).await; // Simulate time taken for each step
                }
            }
        });
    }

    let mut graceful = false; // Will be set to true if the stream closes gracefully
    // Channel for writing results to file
    let (tx_r, rx_r) = unbounded_channel();

    // Get protocol and IP version
    let proto_str = {
        let mut it = m_def
            .configurations
            .iter()
            .map(|c| c.origin.expect("none origin").p_type());
        let first = it.next().unwrap();
        if it.all(|p| p == first) {
            // A single protocol type is used
            first.as_str()
        } else {
            // Multiple protocol types are used
            "multi"
        }
    };

    // Determine Record Route measurements
    let is_record = args.is_record;
    // Determine the file extension based on the output format
    let mut is_parquet = args.is_parquet;

    let extension = if is_parquet { ".parquet" } else { ".csv.gz" };

    let path = Path::new(&args.out_path);
    let file_path = if args.out_path.ends_with('/') || path.is_dir() {
        // Create filename using default convention
        path.join(format!(
            "{}-{proto_str}-{timestamp_start_str}{extension}",
            m_def.m_type().as_str()
        ))
    } else {
        if args.out_path.ends_with(".parquet") {
            is_parquet = true;
        }
        path.to_path_buf()
    };

    // Create the output file
    info!("[CLI] Writing results to {}", file_path.display());
    let file = File::create(file_path).expect("Unable to create file");

    let metadata_args = MetadataArgs {
        hitlist: args.hitlist_path,
        is_shuffle: args.is_shuffle,
        probing_rate: m_def.probing_rate,
        interval: m_def.worker_interval,
        all_workers: &args.worker_map,
        configurations: &m_def.configurations,
        is_responsive: m_def.is_responsive,
        m_type: m_def.m_type(),
    };

    // Check if any configuration has an origin ID
    let is_multi_origin = m_def.configurations.iter().any(|conf| {
        conf.origin
            .as_ref()
            .is_some_and(|origin| origin.origin_id != SINGLE_ORIGIN)
    });

    // Check if any configuration sends CHAOS probes
    let is_chaos = m_def.configurations.iter().any(|conf| {
        conf.origin
            .as_ref()
            .is_some_and(|origin| origin.p_type() == ChaosDns)
    });

    let config = WriteConfig {
        print_to_cli: args.is_cli,
        output_file: file,
        metadata_args,
        m_type: row_m_type,
        is_multi_origin,
        worker_map: args.worker_map.clone(),
        is_record,
        is_chaos,
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

impl CliClient {
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

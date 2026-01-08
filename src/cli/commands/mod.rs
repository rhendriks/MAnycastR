use crate::cli::client::CliClient;
use crate::custom_module::manycastr::Empty;
use bimap::BiHashMap;
use clap::ArgMatches;
use log::info;
use std::error::Error;
use tonic::codec::CompressionEncoding;
use tonic::Request;
pub(crate) mod start;
mod worker_list;

/// Execute the command-line arguments and send the desired commands to the orchestrator.
///
/// # Arguments
/// * `args` - the user-defined command-line arguments
#[tokio::main]
pub async fn execute(args: &ArgMatches) -> Result<(), Box<dyn Error>> {
    let server_address = args.get_one::<String>("orchestrator").unwrap();
    let fqdn = args.get_one::<String>("tls");

    // Connect with orchestrator
    info!("[CLI] Connecting to orchestrator - {server_address}");
    let mut grpc_client = CliClient::connect(server_address, fqdn)
        .await
        .expect("Unable to connect to orchestrator")
        .send_compressed(CompressionEncoding::Zstd);

    // Obtain connected worker information
    let response = grpc_client
        .list_workers(Request::new(Empty::default()))
        .await
        .expect("Connection to orchestrator failed");

    let mut cli_client = CliClient { grpc_client };

    if args.subcommand_matches("worker-list").is_some() {
        worker_list::handle(response).await
    } else if let Some(matches) = args.subcommand_matches("start") {
        // Map to convert hostnames to worker IDs and vice versa
        let worker_map: BiHashMap<u32, String> = response
            .into_inner()
            .workers
            .into_iter()
            .map(|worker| (worker.worker_id, worker.hostname))
            .collect();

        start::handle(matches, &mut cli_client, worker_map).await?
    } else {
        panic!("Unrecognized command");
    };
    Ok(())
}

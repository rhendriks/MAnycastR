use clap::ArgMatches;
use crate::cli::client::CliClient;

/// Perform a live measurement that reads tasks from a pipe, sends them to the orchestrator,
/// and prints the results to stdout.
/// # Arguments
/// * 'matches' - the user-defined command-line arguments
/// * 'grpc_client' - the gRPC client connected to the orchestrator
pub async fn handle(
    matches: &ArgMatches,
    grpc_client: &mut CliClient,
) -> Result<(), Box<dyn std::error::Error>> {
    // TODO
    todo!()
}
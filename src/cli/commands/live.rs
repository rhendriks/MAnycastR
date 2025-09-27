use crate::cli::client::CliClient;
use clap::ArgMatches;

/// Perform a live measurement that reads tasks from a pipe, sends them to the orchestrator,
/// and prints the results to stdout.
/// # Arguments
/// * 'matches' - the user-defined command-line arguments
/// * 'grpc_client' - the gRPC client connected to the orchestrator
pub async fn handle(
    _matches: &ArgMatches,
    _grpc_client: &mut CliClient,
) -> Result<(), Box<dyn std::error::Error>> {
    // TODO
    todo!()
}

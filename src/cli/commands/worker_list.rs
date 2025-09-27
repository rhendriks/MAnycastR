use crate::custom_module::manycastr::Status;
use log::info;
use prettytable::{color, format, row, Attr, Cell, Row, Table};
use tonic::Response;

/// Handle the worker-list command by pretty-printing the list of workers
///
/// # Arguments
///
/// * `response` - The response from the orchestrator containing the list of workers
pub async fn handle(response: Response<Status>) {
    // Perform the worker-list command
    info!("[CLI] Requesting workers list from orchestrator");
    // Pretty print to command-line
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
    table.add_row(Row::new(vec![
        Cell::new("Hostname")
            .with_style(Attr::Bold)
            .with_style(Attr::ForegroundColor(color::GREEN)),
        Cell::new("Worker ID")
            .with_style(Attr::Bold)
            .with_style(Attr::ForegroundColor(color::GREEN)),
        Cell::new("Status")
            .with_style(Attr::Bold)
            .with_style(Attr::ForegroundColor(color::GREEN)),
        Cell::new("Unicast IPv4")
            .with_style(Attr::Bold)
            .with_style(Attr::ForegroundColor(color::GREEN)),
        Cell::new("Unicast IPv6")
            .with_style(Attr::Bold)
            .with_style(Attr::ForegroundColor(color::GREEN)),
    ]));

    let mut connected_workers = 0;
    let mut workers = response.into_inner().workers;
    workers.sort_by(|a, b| a.worker_id.cmp(&b.worker_id));

    for worker in workers {
        let unicast_v4 = if let Some(addr) = &worker.unicast_v4 {
            addr.to_string()
        } else {
            "N/A".to_string()
        };

        let unicast_v6 = if let Some(addr) = &worker.unicast_v6 {
            addr.to_string()
        } else {
            "N/A".to_string()
        };

        table.add_row(row![
            worker.hostname,
            worker.worker_id,
            worker.status,
            unicast_v4,
            unicast_v6
        ]);
        if worker.status != "DISCONNECTED" {
            connected_workers += 1;
        }
    }

    table.printstd();
    info!("[CLI] Total number of connected workers: {connected_workers}");
}

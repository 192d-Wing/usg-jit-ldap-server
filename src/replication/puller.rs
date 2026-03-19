//! Replication puller — periodically fetches identity updates
//! from the central authority and merges them into the local
//! identity schema.

/// Configuration for the replication puller.
pub struct PullerConfig {
    pub central_url: String,
    pub pull_interval_secs: u64,
    pub site_id: String,
}

/// Start the replication pull loop. Runs until the provided
/// cancellation token is triggered.
pub async fn run_puller(_config: PullerConfig) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: periodic fetch, diff, merge
    todo!("replication puller")
}

//! FlowFang Analyzer — traffic analysis engine with HTTP API.
//!
//! Consumes sampled flow records from shared memory, aggregates statistics,
//! generates DPI fingerprints, and exposes a RESTful HTTP API for the TUI
//! and other consumers.

mod api;
mod stats;

use anyhow::{Context, Result};
use clap::Parser;
use flow_common::shm::ShmRingBuf;
use flow_common::types::{DpiFingerprint, FlowSample};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use stats::TrafficStats;

/// FlowFang Analyzer — traffic analysis engine.
#[derive(Parser)]
#[command(name = "flow-analyzer", version)]
struct Args {
    /// Listen address (unix socket or TCP, like Docker daemon)
    #[arg(short, long, default_value = "unix:///var/run/flowfang.sock")]
    listen: String,

    /// Configuration file path (TOML or YAML)
    #[arg(short, long)]
    config: Option<PathBuf>,
}

#[derive(serde::Deserialize)]
struct AnalyzerConfig {
    #[serde(default = "default_listen")]
    listen: String,
    #[serde(default = "default_samples_shm")]
    samples_shm_name: String,
    #[serde(default = "default_rules_shm")]
    rules_shm_name: String,
    #[serde(default = "default_rules_capacity")]
    rules_capacity: usize,
}

fn default_listen() -> String { "unix:///var/run/flowfang.sock".into() }
fn default_samples_shm() -> String { "flowfang-samples".into() }
fn default_rules_shm() -> String { "flowfang-rules".into() }
fn default_rules_capacity() -> usize { 1024 }

/// Shared application state.
pub struct AppState {
    pub stats: RwLock<TrafficStats>,
    pub fingerprints: RwLock<Vec<DpiFingerprint>>,
    pub rules_shm: ShmRingBuf<DpiFingerprint>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    let config = if let Some(path) = &args.config {
        flow_common::config::load_config::<AnalyzerConfig>(path)?
    } else {
        AnalyzerConfig {
            listen: args.listen.clone(),
            samples_shm_name: "flowfang-samples".into(),
            rules_shm_name: "flowfang-rules".into(),
            rules_capacity: 1024,
        }
    };

    log::info!("FlowFang Analyzer starting, listening on {}", config.listen);

    // Open shared memory for samples
    let samples_shm = ShmRingBuf::<FlowSample>::open(&config.samples_shm_name)
        .context("failed to open samples shared memory — is the sampler running?")?;

    log::info!("Samples shared memory opened: flowfang-{}", config.samples_shm_name);

    // Create shared memory for rules
    let rules_shm = ShmRingBuf::<DpiFingerprint>::create(
        &config.rules_shm_name,
        config.rules_capacity,
    )
    .context("failed to create rules shared memory")?;

    log::info!("Rules shared memory created: flowfang-{}", config.rules_shm_name);

    // Shared state
    let state = Arc::new(AppState {
        stats: RwLock::new(TrafficStats::default()),
        fingerprints: RwLock::new(Vec::new()),
        rules_shm,
    });

    // Spawn background task: consume samples from shared memory
    let bg_state = state.clone();
    std::thread::spawn(move || {
        log::info!("Background sample consumer started");
        loop {
            match samples_shm.try_pop() {
                Ok(Some(sample)) => {
                    if let Ok(mut stats) = bg_state.stats.try_write() {
                        stats.record_sample(&sample);
                    }
                }
                Ok(None) => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => {
                    log::error!("Shared memory read error: {}", e);
                    break;
                }
            }
        }
    });

    // Start HTTP API server
    api::serve(&config.listen, state).await?;

    Ok(())
}
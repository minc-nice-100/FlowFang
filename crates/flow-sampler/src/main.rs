//! FlowFang Sampler — eBPF packet sampling daemon.
//!
//! Loads the sampler eBPF program, attaches it to a network interface's
//! TC ingress hook, and writes sampled flow records to shared memory for
//! the analyzer to consume.

use anyhow::{Context, Result};
use clap::Parser;
use flow_common::shm::ShmRingBuf;
use flow_common::types::FlowSample;
use flow_ebpf::sampler::SamplerBpf;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// FlowFang Sampler — eBPF packet sampling daemon.
#[derive(Parser)]
#[command(name = "flow-sampler", version)]
struct Args {
    /// Network interface to attach the sampler to
    #[arg(short, long, default_value = "eth0")]
    iface: String,

    /// Path to the compiled sampler eBPF object file
    #[arg(long, default_value = "/usr/lib/flowfang/sampler.bpf.o")]
    ebpf_path: PathBuf,

    /// Configuration file path (TOML or YAML)
    #[arg(short, long)]
    config: Option<PathBuf>,
}

/// Sampler configuration loaded from TOML/YAML.
#[derive(serde::Deserialize)]
struct SamplerConfig {
    /// Network interface to sample
    #[serde(default = "default_iface")]
    iface: String,
    /// Sampling rate: 1/N packets are sampled
    #[serde(default = "default_sampling_rate")]
    sampling_rate: u32,
    /// Shared memory buffer name
    #[serde(default = "default_shm_name")]
    shm_name: String,
    /// Shared memory buffer capacity (number of FlowSample records)
    #[serde(default = "default_shm_capacity")]
    shm_capacity: usize,
}

fn default_iface() -> String { "eth0".into() }
fn default_sampling_rate() -> u32 { 1 }
fn default_shm_name() -> String { "flowfang-samples".into() }
fn default_shm_capacity() -> usize { 65536 }

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    let config = if let Some(config_path) = &args.config {
        flow_common::config::load_config::<SamplerConfig>(config_path)?
    } else {
        SamplerConfig {
            iface: args.iface.clone(),
            sampling_rate: 1,
            shm_name: "flowfang-samples".into(),
            shm_capacity: 65536,
        }
    };

    log::info!(
        "FlowFang Sampler starting on {} (sampling rate: 1/{})",
        config.iface,
        config.sampling_rate
    );

    // Create shared memory ring buffer for exporting samples
    let shm = ShmRingBuf::<FlowSample>::create(&config.shm_name, config.shm_capacity)
        .context("failed to create shared memory ring buffer")?;

    log::info!(
        "Shared memory ring buffer created: flowfang-{} ({} slots)",
        config.shm_name,
        config.shm_capacity
    );

    // Load and attach the eBPF sampler
    let mut sampler = SamplerBpf::load(&args.ebpf_path)
        .context("failed to load sampler eBPF program")?;

    sampler
        .attach(&config.iface)
        .context("failed to attach sampler")?;

    log::info!("Sampler eBPF program loaded and attached");

    // Signal handling
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    setup_signal_handler(r);

    // Main loop: consume ringbuf and write to shared memory
    let ringbuf = sampler.ringbuf().context("failed to get ring buffer handle")?;

    log::info!("Entering main loop — consuming ringbuf and writing to shared memory");

    while running.load(Ordering::SeqCst) {
        if let Some(item) = ringbuf.next() {
            let sample: FlowSample = item.as_ref();
            match shm.try_push(sample) {
                Ok(true) => { /* sample written */ }
                Ok(false) => {
                    log::warn!("Shared memory ring buffer full, dropping sample");
                }
                Err(e) => {
                    log::error!("Shared memory write error: {}", e);
                    break;
                }
            }
        }
    }

    log::info!("Shutting down sampler...");
    sampler.detach().context("failed to detach sampler")?;
    log::info!("Sampler detached. Goodbye.");

    Ok(())
}

/// Set up signal handling for graceful shutdown.
#[cfg(unix)]
fn setup_signal_handler(running: Arc<AtomicBool>) {
    let mut signals = signal_hook::iterator::Signals::new(&[
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
    ])
    .expect("failed to register signal handlers");
    std::thread::spawn(move || {
        for sig in signals.forever() {
            log::info!("Received signal {}, shutting down...", sig);
            running.store(false, Ordering::SeqCst);
            break;
        }
    });
}

#[cfg(not(unix))]
fn setup_signal_handler(_running: Arc<AtomicBool>) {
    log::warn!("Signal handling not available on this platform");
}
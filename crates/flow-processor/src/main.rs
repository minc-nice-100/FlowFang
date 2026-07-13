//! FlowFang Processor — eBPF DPI fingerprint matching daemon.
//!
//! Loads the processor eBPF program, attaches it to a network interface's
//! TC ingress hook, and syncs fingerprint rules from shared memory to the
//! BPF maps for kernel-side matching.

use anyhow::{Context, Result};
use clap::Parser;
use flow_common::shm::ShmRingBuf;
use flow_common::types::RuleUpdate;
use flow_ebpf::processor::{DpiPatternBytes, ProcessorBpf};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// FlowFang Processor — eBPF DPI matching daemon.
#[derive(Parser)]
#[command(name = "flow-processor", version)]
struct Args {
    /// Network interface to attach the processor to
    #[arg(short, long, default_value = "eth0")]
    iface: String,

    /// Path to the compiled processor eBPF object file
    #[arg(long, default_value = "/usr/lib/flowfang/processor.bpf.o")]
    ebpf_path: PathBuf,

    /// Configuration file path (TOML or YAML)
    #[arg(short, long)]
    config: Option<PathBuf>,
}

#[derive(serde::Deserialize)]
struct ProcessorConfig {
    #[serde(default = "default_iface")]
    iface: String,
    #[serde(default = "default_rules_shm")]
    rules_shm_name: String,
    #[serde(default = "default_rules_capacity")]
    rules_capacity: usize,
}

fn default_iface() -> String { "eth0".into() }
fn default_rules_shm() -> String { "flowfang-rules".into() }
fn default_rules_capacity() -> usize { 1024 }

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    let config = if let Some(path) = &args.config {
        flow_common::config::load_config::<ProcessorConfig>(path)?
    } else {
        ProcessorConfig {
            iface: args.iface.clone(),
            rules_shm_name: "flowfang-rules".into(),
            rules_capacity: 1024,
        }
    };

    log::info!("FlowFang Processor starting on {}", config.iface);

    // Open shared memory for receiving rules from the analyzer
    let rules_shm = ShmRingBuf::<RuleUpdate>::open(&config.rules_shm_name)
        .context("failed to open rules shared memory — is the analyzer running?")?;

    log::info!("Rules shared memory opened: flowfang-{}", config.rules_shm_name);

    // Load and attach the processor eBPF program
    let mut processor = ProcessorBpf::load(&args.ebpf_path)
        .context("failed to load processor eBPF program")?;

    processor
        .attach(&config.iface)
        .context("failed to attach processor")?;

    log::info!("Processor eBPF program loaded and attached");

    // Signal handling
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    #[cfg(unix)]
    {
        let mut signals = signal_hook::iterator::Signals::new(&[
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGINT,
        ])?;
        std::thread::spawn(move || {
            for sig in signals.forever() {
                log::info!("Received signal {}, shutting down...", sig);
                r.store(false, Ordering::SeqCst);
                break;
            }
        });
    }

    log::info!("Entering main loop — syncing rules from shared memory");

    while running.load(Ordering::SeqCst) {
        // Poll the shared memory for new rules
        while let Ok(Some(rule)) = rules_shm.try_pop() {
            if rule.action == RuleUpdate::DELETE {
                // Decode UUID from bytes
                let id = u128::from_be_bytes(rule.id) as u32;
                processor.remove_rule(id)?;
                log::info!("Rule deleted: {}", hex::encode(&rule.name[..rule.name_len as usize]));
            } else {
                let id = u128::from_be_bytes(rule.id) as u32;
                let pattern = DpiPatternBytes {
                    pattern_type: rule.pattern_type,
                    offset: rule.offset,
                    length: rule.pattern_len,
                    data: rule.pattern_data,
                };
                processor.write_rule(id, pattern, rule.action)?;
                log::info!(
                    "Rule synced: {} (action: {})",
                    String::from_utf8_lossy(&rule.name[..rule.name_len as usize]),
                    rule.action
                );
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    log::info!("Shutting down processor...");
    processor.detach().context("failed to detach processor")?;
    log::info!("Processor detached. Goodbye.");

    Ok(())
}
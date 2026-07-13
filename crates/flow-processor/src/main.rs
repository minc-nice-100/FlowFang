//! FlowFang Processor — eBPF DPI fingerprint matching daemon.
//!
//! Loads the processor eBPF program, attaches it to a network interface's
//! TC ingress hook, and syncs fingerprint rules from shared memory to the
//! BPF maps for kernel-side matching.

use anyhow::{Context, Result};
use clap::Parser;
use flow_common::shm::ShmRingBuf;
use flow_common::types::{DpiFingerprint, DpiPattern, ProcessorAction};
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
    let rules_shm = ShmRingBuf::<DpiFingerprint>::open(&config.rules_shm_name)
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

    // Track known rule IDs for delta detection
    let mut known_ids: Vec<u32> = Vec::new();

    log::info!("Entering main loop — syncing rules from shared memory");

    while running.load(Ordering::SeqCst) {
        // Poll the shared memory for new rules
        while let Ok(Some(rule)) = rules_shm.try_pop() {
            let id = rule.id.as_u128() as u32; // Truncate UUID to u32 for BPF map key

            let pattern_bytes = pattern_to_bpf(&rule.pattern);

            let action_code = match rule.action {
                ProcessorAction::Pass => 0u32,
                ProcessorAction::Drop => 1u32,
                ProcessorAction::Mark { mark } => mark,
            };

            processor.write_rule(id, pattern_bytes, action_code)?;
            if !known_ids.contains(&id) {
                known_ids.push(id);
            }
            log::info!("Rule synced: {} (action: {:?})", rule.name, rule.action);
        }

        // Small sleep to avoid busy-waiting
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    log::info!("Shutting down processor...");
    processor.detach().context("failed to detach processor")?;
    log::info!("Processor detached. Goodbye.");

    Ok(())
}

/// Convert a DpiPattern to the fixed-size BPF representation.
fn pattern_to_bpf(pattern: &DpiPattern) -> DpiPatternBytes {
    match pattern {
        DpiPattern::ExactMatch { offset, bytes } => {
            let mut data = [0u8; 64];
            let len = bytes.len().min(64);
            data[..len].copy_from_slice(&bytes[..len]);
            DpiPatternBytes {
                pattern_type: 0,
                offset: *offset,
                length: len as u16,
                data,
            }
        }
        DpiPattern::ByteSeq { sequence } => {
            let mut data = [0u8; 64];
            let len = sequence.len().min(64);
            data[..len].copy_from_slice(&sequence[..len]);
            DpiPatternBytes {
                pattern_type: 1,
                offset: 0,
                length: len as u16,
                data,
            }
        }
        _ => DpiPatternBytes {
            pattern_type: 0xFF,
            offset: 0,
            length: 0,
            data: [0u8; 64],
        },
    }
}
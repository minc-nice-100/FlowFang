//! eBPF program loading and management.
//!
//! Wraps Aya to provide safe, high-level interfaces for loading and
//! attaching FlowFang's eBPF programs.

pub mod sampler;

use aya::programs::Tc;
use aya::Ebpf;
use anyhow::Context;
use std::path::Path;

/// Load an eBPF object file from the given path.
pub fn load_ebpf(path: &Path) -> anyhow::Result<Ebpf> {
    let bytes = std::fs::read(path).context("failed to read eBPF object file")?;
    Ebpf::load(&bytes).context("failed to load eBPF program")
}
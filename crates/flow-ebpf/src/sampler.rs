//! Sampler eBPF program loader.
//!
//! Loads the compiled `sampler.bpf.o` and provides access to its ring buffer
//! for consuming sampled flow records.

use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::programs::TcAttachType;
use aya::Ebpf;
use std::path::Path;

/// Loaded sampler eBPF program.
pub struct SamplerBpf {
    ebpf: Ebpf,
    attached: Option<String>,
}

impl SamplerBpf {
    /// Load the sampler eBPF program from a compiled `.o` file.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).context("failed to read sampler eBPF object file")?;
        let ebpf = Ebpf::load(&bytes).context("failed to load sampler eBPF program")?;

        Ok(Self {
            ebpf,
            attached: None,
        })
    }

    /// Attach the sampler to the TC ingress hook on the given interface.
    pub fn attach(&mut self, iface: &str) -> Result<()> {
        let program = self
            .ebpf
            .program_mut("sampler")
            .context("sampler program not found in eBPF object")?;

        program
            .tc()
            .context("sampler program is not a TC classifier")?
            .load()
            .context("failed to load sampler TC program")?;

        program
            .tc()
            .context("sampler program is not a TC classifier")?
            .attach(iface, TcAttachType::Ingress)
            .context(format!("failed to attach sampler to {}", iface))?;

        self.attached = Some(iface.to_string());
        log::info!("Sampler attached to {} (ingress)", iface);
        Ok(())
    }

    /// Detach the sampler from the interface and unload the program.
    pub fn detach(&mut self) -> Result<()> {
        if let Some(iface) = self.attached.take() {
            let program = self
                .ebpf
                .program_mut("sampler")
                .context("sampler program not found")?;

            program
                .tc()
                .context("sampler program is not a TC classifier")?
                .detach()
                .context(format!("failed to detach sampler from {}", iface))?;

            log::info!("Sampler detached from {}", iface);
        }
        Ok(())
    }

    /// Get a handle to the ring buffer for consuming sampled flow records.
    pub fn ringbuf(&self) -> Result<RingBuf<'_>> {
        self.ebpf
            .map_mut("SAMPLES")
            .context("SAMPLES map not found in eBPF object")?
            .try_into()
            .context("SAMPLES map is not a RingBuf")
    }
}

impl Drop for SamplerBpf {
    fn drop(&mut self) {
        if self.attached.is_some() {
            let _ = self.detach();
        }
    }
}
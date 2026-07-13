//! Processor eBPF program loader.
//!
//! Loads the compiled `processor.bpf.o` and provides access to its BPF maps
//! for writing fingerprint rules and actions.

use anyhow::{Context, Result};
use aya::maps::HashMap;
use aya::programs::TcAttachType;
use aya::Ebpf;
use std::path::Path;

/// Fingerprint rule data as stored in the BPF map.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct DpiPatternBytes {
    pub pattern_type: u8,
    pub offset: u16,
    pub length: u16,
    pub data: [u8; 64],
}

/// Loaded processor eBPF program.
pub struct ProcessorBpf {
    ebpf: Ebpf,
    attached: Option<String>,
}

impl ProcessorBpf {
    /// Load the processor eBPF program from a compiled `.o` file.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).context("failed to read processor eBPF object file")?;
        let ebpf = Ebpf::load(&bytes).context("failed to load processor eBPF program")?;

        Ok(Self {
            ebpf,
            attached: None,
        })
    }

    /// Attach the processor to the TC ingress hook on the given interface.
    pub fn attach(&mut self, iface: &str) -> Result<()> {
        let program = self
            .ebpf
            .program_mut("processor")
            .context("processor program not found in eBPF object")?;

        program
            .tc()
            .context("processor program is not a TC classifier")?
            .load()
            .context("failed to load processor TC program")?;

        program
            .tc()
            .context("processor program is not a TC classifier")?
            .attach(iface, TcAttachType::Ingress)
            .context(format!("failed to attach processor to {}", iface))?;

        self.attached = Some(iface.to_string());
        log::info!("Processor attached to {} (ingress)", iface);
        Ok(())
    }

    /// Detach the processor from the interface.
    pub fn detach(&mut self) -> Result<()> {
        if let Some(iface) = self.attached.take() {
            let program = self
                .ebpf
                .program_mut("processor")
                .context("processor program not found")?;

            program
                .tc()
                .context("processor program is not a TC classifier")?
                .detach()
                .context(format!("failed to detach processor from {}", iface))?;

            log::info!("Processor detached from {}", iface);
        }
        Ok(())
    }

    /// Get a mutable reference to the FINGERPRINTS map.
    pub fn fingerprints_map(&mut self) -> Result<HashMap<'_, u32, DpiPatternBytes>> {
        self.ebpf
            .map_mut("FINGERPRINTS")
            .context("FINGERPRINTS map not found")?
            .try_into()
            .context("FINGERPRINTS map is not a HashMap")
    }

    /// Get a mutable reference to the ACTIONS map.
    pub fn actions_map(&mut self) -> Result<HashMap<'_, u32, u32>> {
        self.ebpf
            .map_mut("ACTIONS")
            .context("ACTIONS map not found")?
            .try_into()
            .context("ACTIONS map is not a HashMap")
    }

    /// Write a fingerprint rule to the BPF maps.
    pub fn write_rule(&mut self, id: u32, pattern: DpiPatternBytes, action: u32) -> Result<()> {
        self.fingerprints_map()?.insert(id, pattern, 0)?;
        self.actions_map()?.insert(id, action, 0)?;
        log::debug!("Rule {} written to processor BPF maps", id);
        Ok(())
    }

    /// Remove a fingerprint rule from the BPF maps.
    pub fn remove_rule(&mut self, id: u32) -> Result<()> {
        let _ = self.fingerprints_map()?.remove(&id);
        let _ = self.actions_map()?.remove(&id);
        log::debug!("Rule {} removed from processor BPF maps", id);
        Ok(())
    }
}

impl Drop for ProcessorBpf {
    fn drop(&mut self) {
        if self.attached.is_some() {
            let _ = self.detach();
        }
    }
}
//! eBPF program loading and management.
//!
//! Wraps Aya to provide safe, high-level interfaces for loading and
//! attaching FlowFang's eBPF programs.

pub mod processor;
pub mod sampler;

pub use processor::ProcessorBpf;
pub use sampler::SamplerBpf;
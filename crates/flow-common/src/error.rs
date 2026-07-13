//! Error types for FlowFang.

use thiserror::Error;

/// The canonical error type for the project.
#[derive(Debug, Error)]
pub enum FlowError {
    /// Shared memory errors.
    #[error("shared memory error: {0}")]
    Shm(String),

    /// eBPF loading or attach errors.
    #[error("ebpf error: {0}")]
    Ebpf(String),

    /// Configuration parsing errors.
    #[error("config error: {0}")]
    Config(String),

    /// Wrapped I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
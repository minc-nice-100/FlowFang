//! Configuration loading.
//!
//! Supports TOML and YAML formats, selected by file extension.

use serde::de::DeserializeOwned;
use std::path::Path;

use crate::error::FlowError;

/// Load a configuration struct from a file.
///
/// Format is determined by file extension:
/// - `.toml` → TOML
/// - `.yaml`, `.yml` → YAML
pub fn load_config<T: DeserializeOwned>(path: &Path) -> Result<T, FlowError> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    let content = std::fs::read_to_string(path).map_err(FlowError::Io)?;

    match ext {
        "toml" => {
            toml::from_str(&content).map_err(|e| FlowError::Config(format!("TOML parse error: {}", e)))
        }
        "yaml" | "yml" => serde_yaml::from_str(&content)
            .map_err(|e| FlowError::Config(format!("YAML parse error: {}", e))),
        other => Err(FlowError::Config(format!(
            "unsupported config format: .{} (expected .toml, .yaml, or .yml)",
            other
        ))),
    }
}
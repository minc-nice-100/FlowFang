//! Configuration loading.
//!
//! Supports TOML and YAML formats, selected by file extension.
//! Configuration is resolved with this priority:
//! 1. CLI argument (explicit path)
//! 2. `FLOWFANG_CONFIG` environment variable
//! 3. `/etc/flowfang/config.{toml,yaml,yml}`
//! 4. `./config/default.{toml,yaml}`

use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};

use crate::error::FlowError;

/// Load a configuration struct from a specific file path.
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

/// Resolve a configuration file path using the priority chain:
/// 1. CLI argument (if provided)
/// 2. `FLOWFANG_CONFIG` environment variable
/// 3. `/etc/flowfang/config.{toml,yaml,yml}`
/// 4. `./config/default.{toml,yaml}`
pub fn resolve_config_path(cli_path: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = cli_path {
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }

    if let Ok(env_path) = std::env::var("FLOWFANG_CONFIG") {
        let p = PathBuf::from(&env_path);
        if p.exists() {
            return Some(p);
        }
    }

    for ext in &["toml", "yaml", "yml"] {
        let p = PathBuf::from(format!("/etc/flowfang/config.{}", ext));
        if p.exists() {
            return Some(p);
        }
    }

    for ext in &["toml", "yaml"] {
        let p = PathBuf::from(format!("./config/default.{}", ext));
        if p.exists() {
            return Some(p);
        }
    }

    None
}
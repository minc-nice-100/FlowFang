use flow_common::config::load_config;
use serde::Deserialize;
use std::io::Write;
use tempfile::NamedTempFile;

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct TestConfig {
    name: String,
    port: u16,
    enabled: bool,
}

#[test]
fn load_toml_config() {
    let toml_content = r#"
name = "test-service"
port = 9090
enabled = true
"#;
    let mut file = NamedTempFile::with_suffix(".toml").unwrap();
    file.write_all(toml_content.as_bytes()).unwrap();

    let config: TestConfig = load_config(file.path()).unwrap();
    assert_eq!(
        config,
        TestConfig {
            name: "test-service".into(),
            port: 9090,
            enabled: true,
        }
    );
}

#[test]
fn load_yaml_config() {
    let yaml_content = r#"
name: test-service
port: 9090
enabled: true
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    file.write_all(yaml_content.as_bytes()).unwrap();

    let config: TestConfig = load_config(file.path()).unwrap();
    assert_eq!(
        config,
        TestConfig {
            name: "test-service".into(),
            port: 9090,
            enabled: true,
        }
    );
}

#[test]
fn load_yml_extension() {
    let yaml_content = r#"
name: yml-test
port: 8080
enabled: false
"#;
    let mut file = NamedTempFile::with_suffix(".yml").unwrap();
    file.write_all(yaml_content.as_bytes()).unwrap();

    let config: TestConfig = load_config(file.path()).unwrap();
    assert_eq!(
        config,
        TestConfig {
            name: "yml-test".into(),
            port: 8080,
            enabled: false,
        }
    );
}

#[test]
fn file_not_found_returns_error() {
    let result = load_config::<TestConfig>(std::path::Path::new("nonexistent_file.toml"));
    assert!(result.is_err());
}

#[test]
fn unsupported_extension_returns_error() {
    let mut file = NamedTempFile::with_suffix(".json").unwrap();
    file.write_all(b"{}").unwrap();

    let result = load_config::<TestConfig>(file.path());
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("unsupported config format"));
}

#[test]
fn invalid_toml_returns_error() {
    let mut file = NamedTempFile::with_suffix(".toml").unwrap();
    file.write_all(b"not valid toml {{{").unwrap();

    let result = load_config::<TestConfig>(file.path());
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("TOML parse error"));
}
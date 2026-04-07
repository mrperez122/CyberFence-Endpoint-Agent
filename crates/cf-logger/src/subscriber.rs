//! Initializes the global tracing subscriber.
//!
//! Call `init_subscriber()` once at agent startup before any
//! other logging calls are made.

use anyhow::Result;
use cf_config::AgentConfig;
use chrono::Local;
use std::path::PathBuf;
use tracing_subscriber::{
    fmt::{self},
    EnvFilter,
    prelude::*,
};

/// Returns the log file path for today's date.
///
/// | Platform | Path |
/// |----------|------|
/// | Windows  | `%APPDATA%\CyberFence\logs\agent-YYYY-MM-DD.jsonl` |
/// | macOS    | `~/Library/Logs/CyberFence/agent-YYYY-MM-DD.jsonl` |
/// | Linux    | `/var/log/cyberfence/agent-YYYY-MM-DD.jsonl` |
pub fn log_file_path(config: &AgentConfig) -> PathBuf {
    let date = Local::now().format("%Y-%m-%d").to_string();
    let filename = format!("agent-{}.jsonl", date);

    if let Some(custom_dir) = &config.log_dir {
        return custom_dir.join(&filename);
    }

    #[cfg(target_os = "windows")]
    {
        let base = std::env::var("APPDATA").unwrap_or_else(|_| "C:\\Users\\Default\\AppData\\Roaming".into());
        PathBuf::from(base).join("CyberFence").join("logs").join(filename)
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        PathBuf::from(home).join("Library").join("Logs").join("CyberFence").join(filename)
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        PathBuf::from("/tmp/cyberfence/logs").join(filename)
    }
}

/// Initialize the global tracing subscriber.
///
/// Outputs JSON-formatted log lines to:
/// - **stdout** (human-readable, ANSI colours in dev mode)
/// - **log file** (structured JSON, one record per line)
///
/// The log level is read from `config.log_level`, but can be
/// overridden at runtime with the `RUST_LOG` environment variable.
pub fn init_subscriber(config: &AgentConfig) -> Result<()> {
    let log_path = log_file_path(config);

    // Ensure log directory exists
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    // EnvFilter: RUST_LOG overrides config, then fall back to config level
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    // File layer — JSON, no ANSI
    let file_layer = fmt::layer()
        .json()
        .with_writer(log_file)
        .with_ansi(false)
        .with_target(true)
        .with_thread_ids(false)
        .with_line_number(false);

    // Stdout layer — pretty for development
    let stdout_layer = fmt::layer()
        .with_writer(std::io::stdout)
        .with_ansi(true)
        .with_target(true);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(file_layer)
        .with(stdout_layer)
        .init();

    tracing::info!(
        log_file = %log_path.display(),
        level = %config.log_level,
        "CyberFence logger initialized"
    );

    Ok(())
}

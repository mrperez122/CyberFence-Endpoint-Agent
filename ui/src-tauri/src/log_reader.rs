//! Log reader — parses the JSONL scan log files written by cf-scanner.
//!
//! This is how the dashboard reads real scan results without a named pipe:
//! it parses the same structured JSONL files that `scan_logger.rs` writes.
//!
//! Phase 3: this module is replaced by named pipe IPC calls to cf-agent.
//! The data structures here mirror `scan_logger::ScanLogRecord` exactly.

use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

// ── Scan log record (mirrors cf-scanner::scan_logger::ScanLogRecord) ─────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanLogRecord {
    pub id:                  String,
    pub scanned_at:          String,
    pub path:                String,
    pub extension:           String,
    pub size_bytes:          Option<u64>,
    pub verdict:             String,
    pub threat_name:         Option<String>,
    pub severity:            String,
    pub duration_ms:         u64,
    pub triggered_by_event:  Option<String>,
    pub action:              String,
}

// ── Log file path resolution ──────────────────────────────────────────────────

/// Returns the path to today's scan log file.
pub fn scan_log_path(date_str: &str) -> PathBuf {
    log_dir().join(format!("scans-{}.jsonl", date_str))
}

/// Returns the platform-specific log directory.
pub fn log_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var("APPDATA")
            .unwrap_or_else(|_| r"C:\Users\Default\AppData\Roaming".into());
        PathBuf::from(base).join("CyberFence").join("logs")
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        PathBuf::from(home).join("Library").join("Logs").join("CyberFence")
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        PathBuf::from("/tmp/cyberfence/logs")
    }
}

// ── Reader functions ──────────────────────────────────────────────────────────

/// Read all scan log records from today's log file.
/// Returns an empty vec if the file doesn't exist yet.
pub fn read_today_scans() -> Vec<ScanLogRecord> {
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    read_scan_log(&scan_log_path(&today))
}

/// Read all scan log records from a specific log file.
pub fn read_scan_log(path: &PathBuf) -> Vec<ScanLogRecord> {
    let file = match std::fs::File::open(path) {
        Ok(f)  => f,
        Err(_) => return vec![],
    };

    let reader = BufReader::new(file);
    let mut records = Vec::new();

    for line in reader.lines().flatten() {
        if line.trim().is_empty() {
            continue;
        }
        // The log file uses snake_case keys — try both formats
        if let Ok(record) = serde_json::from_str::<ScanLogRecord>(&line) {
            records.push(record);
        }
    }

    // Most recent first
    records.reverse();
    records
}

/// Read scan records from the past N days.
pub fn read_recent_scans(days: u32) -> Vec<ScanLogRecord> {
    let mut all = Vec::new();
    for d in 0..days {
        let date = chrono::Local::now()
            .checked_sub_days(chrono::Days::new(d as u64))
            .unwrap_or_else(chrono::Local::now);
        let date_str = date.format("%Y-%m-%d").to_string();
        let path = scan_log_path(&date_str);
        all.extend(read_scan_log(&path));
    }
    all
}

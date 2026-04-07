//! ScanLogger — dedicated structured log writer for scan results.
//!
//! Writes one JSON line per scan to a separate file:
//!   `scans-YYYY-MM-DD.jsonl`
//!
//! This is SEPARATE from the main agent log (which tracks file events).
//! The scan log is the security audit trail that the dashboard Event Log
//! view will read in Phase 3.
//!
//! # Log format (one JSON object per line)
//!
//! ```json
//! {
//!   "id":                "550e8400-...",
//!   "scanned_at":        "2026-04-07T14:00:00.123Z",
//!   "path":              "C:\\Users\\Carlos\\Downloads\\setup.exe",
//!   "extension":         "exe",
//!   "size_bytes":        2048576,
//!   "verdict":           "INFECTED",
//!   "threat_name":       "Win.Trojan.Generic",
//!   "severity":          "CRITICAL",
//!   "duration_ms":       842,
//!   "triggered_by_event":"a1b2c3d4-...",
//!   "action":            "QUARANTINED"
//! }
//! ```

use std::io::Write;
use std::path::PathBuf;

use anyhow::Result;
use cf_common::scan::{ScanResult, ScanVerdict};
use chrono::Local;
use serde::Serialize;

// ── Scan log record ───────────────────────────────────────────────────────────

/// Flattened scan record for the JSONL log file.
/// More human-readable than the raw `ScanResult` struct.
#[derive(Debug, Serialize)]
pub struct ScanLogRecord {
    pub id:                 String,
    pub scanned_at:         String,
    pub path:               String,
    pub extension:          String,
    pub size_bytes:         Option<u64>,
    pub verdict:            String,       // "CLEAN" | "INFECTED" | "SUSPICIOUS" | "ERROR" | "SKIPPED"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_name:        Option<String>, // populated for INFECTED / SUSPICIOUS
    pub severity:           String,       // "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    pub duration_ms:        u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triggered_by_event: Option<String>,
    pub action:             String,       // "LOGGED" | "QUARANTINED" | "SKIPPED"
}

impl ScanLogRecord {
    pub fn from_result(result: &ScanResult, action: &str) -> Self {
        let (verdict_str, threat_name) = match &result.verdict {
            ScanVerdict::Infected(name)   => ("INFECTED".to_string(),  Some(name.clone())),
            ScanVerdict::Suspicious(name) => ("SUSPICIOUS".to_string(), Some(name.clone())),
            ScanVerdict::Clean            => ("CLEAN".to_string(),      None),
            ScanVerdict::Error(msg)       => ("ERROR".to_string(),      Some(msg.clone())),
            ScanVerdict::Skipped(reason)  => ("SKIPPED".to_string(),    Some(reason.clone())),
        };

        let extension = result.path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        Self {
            id:                 result.id.to_string(),
            scanned_at:         result.scanned_at.to_rfc3339(),
            path:               result.path.display().to_string(),
            extension,
            size_bytes:         result.size_bytes,
            verdict:            verdict_str,
            threat_name,
            severity:           result.severity().to_string(),
            duration_ms:        result.duration_ms,
            triggered_by_event: result.triggered_by_event.map(|id| id.to_string()),
            action:             action.to_string(),
        }
    }
}

// ── ScanLogger ────────────────────────────────────────────────────────────────

/// Writes scan results to a rotating daily JSONL file.
pub struct ScanLogger {
    log_dir: PathBuf,
}

impl ScanLogger {
    pub fn new(log_dir: PathBuf) -> Self {
        Self { log_dir }
    }

    /// Create a `ScanLogger` with the platform-default log directory.
    pub fn with_default_dir() -> Self {
        Self::new(default_log_dir())
    }

    /// Append a scan result to today's scan log file.
    pub fn write(&self, result: &ScanResult, action: &str) -> Result<()> {
        let log_path = self.today_log_path();

        // Ensure directory exists
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let record = ScanLogRecord::from_result(result, action);
        let line   = serde_json::to_string(&record)?;

        // Append one line to the log file
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;

        writeln!(file, "{}", line)?;
        Ok(())
    }

    /// Path to today's scan log file.
    pub fn today_log_path(&self) -> PathBuf {
        let date = Local::now().format("%Y-%m-%d").to_string();
        self.log_dir.join(format!("scans-{}.jsonl", date))
    }
}

// ── Platform-default log directory ───────────────────────────────────────────

fn default_log_dir() -> PathBuf {
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use cf_common::scan::{ScanResult, ScanVerdict};
    use chrono::Utc;
    use tempfile::tempdir;
    use uuid::Uuid;

    fn make_result(verdict: ScanVerdict) -> ScanResult {
        ScanResult {
            id:                  Uuid::new_v4(),
            scanned_at:          Utc::now(),
            path:                std::path::PathBuf::from(r"C:\Downloads\test.exe"),
            size_bytes:          Some(1024),
            triggered_by_event:  Some(Uuid::new_v4()),
            duration_ms:         150,
            verdict,
            definitions_version: None,
        }
    }

    #[test]
    fn writes_infected_record_to_jsonl() {
        let dir    = tempdir().unwrap();
        let logger = ScanLogger::new(dir.path().to_path_buf());
        let result = make_result(ScanVerdict::Infected("Eicar-Signature".to_string()));

        logger.write(&result, "QUARANTINED").unwrap();

        let log_path = logger.today_log_path();
        assert!(log_path.exists(), "log file should be created");

        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(!content.is_empty(), "log file should not be empty");

        // Parse the JSON line
        let record: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(record["verdict"], "INFECTED");
        assert_eq!(record["threat_name"], "Eicar-Signature");
        assert_eq!(record["severity"], "CRITICAL");
        assert_eq!(record["action"], "QUARANTINED");
        assert_eq!(record["duration_ms"], 150);
    }

    #[test]
    fn writes_clean_record_to_jsonl() {
        let dir    = tempdir().unwrap();
        let logger = ScanLogger::new(dir.path().to_path_buf());
        let result = make_result(ScanVerdict::Clean);

        logger.write(&result, "LOGGED").unwrap();

        let content = std::fs::read_to_string(logger.today_log_path()).unwrap();
        let record: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(record["verdict"], "CLEAN");
        assert_eq!(record["severity"], "INFO");
        // threat_name field should be absent for clean files
        assert!(record.get("threat_name").is_none() || record["threat_name"].is_null());
    }

    #[test]
    fn multiple_results_each_on_own_line() {
        let dir    = tempdir().unwrap();
        let logger = ScanLogger::new(dir.path().to_path_buf());

        logger.write(&make_result(ScanVerdict::Clean),                                 "LOGGED").unwrap();
        logger.write(&make_result(ScanVerdict::Infected("Test".to_string())),          "QUARANTINED").unwrap();
        logger.write(&make_result(ScanVerdict::Suspicious("Heuristics.X".to_string())),"LOGGED").unwrap();

        let content = std::fs::read_to_string(logger.today_log_path()).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3, "should have 3 JSONL lines");

        for line in &lines {
            let _: serde_json::Value = serde_json::from_str(line)
                .expect("each line should be valid JSON");
        }
    }
}

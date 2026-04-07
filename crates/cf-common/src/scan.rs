//! Scan result types produced by cf-scanner and consumed by cf-logger,
//! cf-broker (Phase 3), and the UI.

use crate::events::Severity;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

// ── ScanVerdict ───────────────────────────────────────────────────────────────

/// The outcome of scanning a single file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScanVerdict {
    /// ClamAV found no threats.
    Clean,
    /// ClamAV found a known malware signature.
    /// The inner string is the ClamAV virus name (e.g. "Eicar-Signature").
    Infected(String),
    /// File matched a heuristic or PUA (Potentially Unwanted Application) rule.
    Suspicious(String),
    /// Scan could not complete — file unreadable, too large, encrypted, etc.
    Error(String),
    /// File was skipped per config rules (too large, excluded extension, etc.)
    Skipped(String),
}

impl ScanVerdict {
    /// Returns true if this verdict requires user action.
    pub fn is_threat(&self) -> bool {
        matches!(self, Self::Infected(_) | Self::Suspicious(_))
    }

    /// Derive a severity level from this verdict.
    pub fn severity(&self) -> Severity {
        match self {
            Self::Infected(_)   => Severity::Critical,
            Self::Suspicious(_) => Severity::Medium,
            Self::Error(_)      => Severity::Low,
            Self::Clean         => Severity::Info,
            Self::Skipped(_)    => Severity::Info,
        }
    }

    /// Short label suitable for logging.
    pub fn label(&self) -> &str {
        match self {
            Self::Infected(_)   => "INFECTED",
            Self::Suspicious(_) => "SUSPICIOUS",
            Self::Error(_)      => "ERROR",
            Self::Clean         => "CLEAN",
            Self::Skipped(_)    => "SKIPPED",
        }
    }
}

impl std::fmt::Display for ScanVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean              => write!(f, "CLEAN"),
            Self::Infected(name)    => write!(f, "INFECTED({})", name),
            Self::Suspicious(name)  => write!(f, "SUSPICIOUS({})", name),
            Self::Error(msg)        => write!(f, "ERROR({})", msg),
            Self::Skipped(reason)   => write!(f, "SKIPPED({})", reason),
        }
    }
}

// ── ScanResult ────────────────────────────────────────────────────────────────

/// The complete result of scanning one file.
/// This is the primary output of cf-scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Unique ID for this scan result record.
    pub id: Uuid,

    /// When this scan completed.
    pub scanned_at: DateTime<Utc>,

    /// The file that was scanned.
    pub path: PathBuf,

    /// File size at time of scan. `None` if it couldn't be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,

    /// The ID of the FileEvent that triggered this scan, if applicable.
    /// `None` for scans triggered by the scheduler (full/quick scan).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triggered_by_event: Option<Uuid>,

    /// How long the scan took in milliseconds.
    pub duration_ms: u64,

    /// The verdict from ClamAV.
    pub verdict: ScanVerdict,

    /// ClamAV definitions version used for this scan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub definitions_version: Option<String>,
}

impl ScanResult {
    /// Returns true if the file needs immediate action.
    pub fn requires_action(&self) -> bool {
        self.verdict.is_threat()
    }

    /// Convenience accessor for severity.
    pub fn severity(&self) -> Severity {
        self.verdict.severity()
    }
}

// ── FullScanProgress ─────────────────────────────────────────────────────────

/// Progress update emitted during a full or quick system scan.
/// These are sent periodically so the UI can show a progress bar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    /// Unique ID of the scan job.
    pub job_id: Uuid,

    /// Total files discovered in this scan job.
    pub total_files: u64,

    /// Files scanned so far.
    pub scanned_files: u64,

    /// Threats found so far.
    pub threats_found: u32,

    /// The file currently being scanned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_file: Option<PathBuf>,

    /// Percentage complete (0–100).
    pub percent: u8,
}

// ── FullScanSummary ───────────────────────────────────────────────────────────

/// Summary emitted when a full or quick scan completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    /// Unique ID of the scan job.
    pub job_id: Uuid,

    /// What type of scan triggered this job.
    pub scan_type: ScanType,

    /// When the scan started.
    pub started_at: DateTime<Utc>,

    /// When the scan completed.
    pub completed_at: DateTime<Utc>,

    /// Total files scanned.
    pub files_scanned: u64,

    /// Number of infected files found.
    pub infected: u32,

    /// Number of suspicious files found.
    pub suspicious: u32,

    /// Number of files that errored during scan.
    pub errors: u32,

    /// Whether the scan was cancelled before completion.
    pub cancelled: bool,
}

impl ScanSummary {
    pub fn total_threats(&self) -> u32 {
        self.infected + self.suspicious
    }

    pub fn duration_secs(&self) -> i64 {
        (self.completed_at - self.started_at).num_seconds()
    }
}

// ── ScanType ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScanType {
    /// Triggered by a file-system event from cf-monitor.
    OnAccess,
    /// Quick scan of high-risk directories (Downloads, Desktop, Temp, Startup).
    QuickScan,
    /// Full scan of all configured drives/paths.
    FullScan,
    /// Manually triggered on a specific file or directory.
    Manual,
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OnAccess  => write!(f, "ON_ACCESS"),
            Self::QuickScan => write!(f, "QUICK_SCAN"),
            Self::FullScan  => write!(f, "FULL_SCAN"),
            Self::Manual    => write!(f, "MANUAL"),
        }
    }
}

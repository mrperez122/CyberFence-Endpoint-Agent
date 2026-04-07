//! Core event types that flow through the CyberFence agent pipeline.
//!
//! # Event lifecycle
//!
//! ```text
//! OS kernel (inotify / ReadDirectoryChangesW / FSEvents)
//!     → cf-monitor   (produces FileEvent)
//!     → Event Bus    (tokio MPSC channel)
//!     → cf-scanner   (consumes FileEvent — Phase 2)
//!     → cf-broker    (aggregates results — Phase 2)
//!     → cf-logger    (persists everything)
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

// ── Severity ──────────────────────────────────────────────────────────────────

/// Threat severity level. Used across the entire pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    /// Informational — no action needed.
    Info,
    /// Low confidence or low-impact indicator.
    Low,
    /// Warrants investigation.
    Medium,
    /// High-confidence threat indicator — alert user.
    High,
    /// Definite threat — immediate action required.
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info     => write!(f, "INFO"),
            Self::Low      => write!(f, "LOW"),
            Self::Medium   => write!(f, "MEDIUM"),
            Self::High     => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ── FileEventKind ─────────────────────────────────────────────────────────────

/// The type of file-system change observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FileEventKind {
    /// A new file was created.
    Created,
    /// An existing file was modified (content or metadata).
    Modified,
    /// A file was deleted.
    Deleted,
    /// A file was renamed. `old_path` in FileEvent will be populated.
    Renamed,
    /// Catch-all for OS events that don't map to the above.
    Other(String),
}

impl std::fmt::Display for FileEventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created      => write!(f, "CREATED"),
            Self::Modified     => write!(f, "MODIFIED"),
            Self::Deleted      => write!(f, "DELETED"),
            Self::Renamed      => write!(f, "RENAMED"),
            Self::Other(s)     => write!(f, "OTHER({})", s),
        }
    }
}

// ── ScanReadiness ─────────────────────────────────────────────────────────────

/// Indicates whether this event should be forwarded to the scan engine.
/// Phase 1: always `PendingScan` — the scanner doesn't exist yet.
/// Phase 2: scanner will change this to `Scanned` after processing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScanReadiness {
    /// File is queued for scanning (scanner not yet implemented).
    PendingScan,
    /// File was scanned — result attached to a future ScanResult event.
    Scanned,
    /// File was excluded by config rules (too large, excluded path, etc.).
    Excluded,
    /// File no longer exists (deleted before scan could run).
    FileGone,
}

// ── FileEvent ─────────────────────────────────────────────────────────────────

/// A single file-system event observed by cf-monitor.
///
/// This is the primary output of the monitoring component and the
/// primary input to the scanning engine (Phase 2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    /// Unique identifier for this event.
    pub id: Uuid,

    /// UTC timestamp when the OS delivered the event to cf-monitor.
    pub timestamp: DateTime<Utc>,

    /// Absolute path of the affected file.
    pub path: PathBuf,

    /// Previous path (only populated for `Renamed` events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_path: Option<PathBuf>,

    /// What happened to the file.
    pub kind: FileEventKind,

    /// File extension, lowercased (e.g. "exe", "pdf"). Empty string if none.
    pub extension: String,

    /// File size in bytes at the time of the event. `None` if the file
    /// was deleted or the metadata could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,

    /// Watched directory this event originated from.
    pub watch_root: PathBuf,

    /// Whether this event should be forwarded to the scan engine.
    pub scan_readiness: ScanReadiness,
}

impl FileEvent {
    /// Create a new FileEvent from raw OS notification data.
    pub fn new(
        path: PathBuf,
        old_path: Option<PathBuf>,
        kind: FileEventKind,
        watch_root: PathBuf,
    ) -> Self {
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Try to read file size — silently ignore errors (file may be gone)
        let size_bytes = std::fs::metadata(&path).ok().map(|m| m.len());

        // Files that no longer exist cannot be scanned
        let scan_readiness = if !path.exists() {
            ScanReadiness::FileGone
        } else {
            ScanReadiness::PendingScan
        };

        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            path,
            old_path,
            kind,
            extension,
            size_bytes,
            watch_root,
            scan_readiness,
        }
    }

    /// Returns true if this event represents a file that should be scanned.
    /// Phase 2: the scanner will call this to decide whether to process the event.
    pub fn is_scannable(&self) -> bool {
        matches!(
            self.scan_readiness,
            ScanReadiness::PendingScan
        ) && matches!(
            self.kind,
            FileEventKind::Created | FileEventKind::Modified | FileEventKind::Renamed
        )
    }
}

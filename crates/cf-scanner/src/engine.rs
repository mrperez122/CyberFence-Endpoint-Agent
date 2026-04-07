//! ScanEngine — on-access malware scanner.
//!
//! Consumes `FileEvent` values from cf-monitor and scans each file via the
//! CyberFence Engine (ClamAV subprocess). Results flow out as `ScanResult`
//! values on the result channel.
//!
//! # How the monitoring service calls this scanner
//!
//! 1. `cf-monitor` produces a `FileEvent` on a `tokio::sync::mpsc` channel.
//! 2. `EventFanout` (agent/main.rs) clones the event to `scanner_tx`.
//! 3. `ScanEngine::run()` reads from `scanner_rx`.
//! 4. For each `is_scannable()` event, it calls `scan_one_file()`.
//! 5. `scan_one_file()` spawns a `spawn_blocking` task that runs clamscan.
//! 6. The `ScanResult` is sent to `result_tx` → `ScanResultWorker`.
//!
//! # On-demand API
//!
//! `ScanEngine::scan_file_now()` is a static async method that lets the
//! dashboard IPC handler, scheduler, or test code request a single-file
//! scan without going through the event channel.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use cf_common::{
    events::FileEvent,
    scan::{ScanResult, ScanVerdict},
};
use cf_config::AgentConfig;
use chrono::Utc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::clamav::{find_clamscan, scan_file};

// ── ScanEngine ────────────────────────────────────────────────────────────────

/// On-access scan engine. Receives file events and scans each scannable file.
pub struct ScanEngine {
    config:     Arc<AgentConfig>,
    event_rx:   mpsc::Receiver<FileEvent>,
    result_tx:  mpsc::Sender<ScanResult>,
    /// Resolved path to the clamscan binary (None = degraded mode)
    clamscan:   Option<PathBuf>,
}

impl ScanEngine {
    /// Create a new `ScanEngine`.
    ///
    /// # Arguments
    /// - `config`    — agent configuration
    /// - `event_rx`  — receives `FileEvent` values from the monitor fanout
    /// - `result_tx` — sends `ScanResult` values to `ScanResultWorker`
    pub fn new(
        config:    AgentConfig,
        event_rx:  mpsc::Receiver<FileEvent>,
        result_tx: mpsc::Sender<ScanResult>,
    ) -> Self {
        let clamscan = if config.scanner.enabled {
            let path = find_clamscan(&config.scanner);
            if path.is_none() {
                warn!(
                    "CyberFence Engine not found — running in monitor-only mode. \
                     File events will be logged but NOT scanned. \
                     Install ClamAV and restart the agent to enable scanning."
                );
            }
            path
        } else {
            info!("Scanning disabled in config (scanner.enabled = false)");
            None
        };

        Self {
            config: Arc::new(config),
            event_rx,
            result_tx,
            clamscan,
        }
    }

    /// Run the engine loop. Reads FileEvents until the channel is closed.
    ///
    /// This method drives the scanner in the background. Run it via
    /// `tokio::spawn(scan_engine.run())` from `agent/src/main.rs`.
    pub async fn run(mut self) -> Result<()> {
        if self.clamscan.is_none() {
            // Degraded mode: drain the channel so the monitor is not blocked
            info!("ScanEngine in degraded mode — draining event channel without scanning");
            while self.event_rx.recv().await.is_some() {}
            return Ok(());
        }

        let clamscan_bin = self.clamscan.unwrap();
        info!(
            binary = %clamscan_bin.display(),
            "ScanEngine started — waiting for file events"
        );

        while let Some(event) = self.event_rx.recv().await {
            if !event.is_scannable() {
                debug!(
                    path      = %event.path.display(),
                    readiness = ?event.scan_readiness,
                    "Skipping non-scannable event"
                );
                continue;
            }

            let config     = Arc::clone(&self.config);
            let result_tx  = self.result_tx.clone();
            let clamscan   = clamscan_bin.clone();

            // Run each file scan in a blocking thread.
            // clamscan is a synchronous subprocess — spawn_blocking keeps the
            // tokio executor free for other tasks.
            tokio::task::spawn_blocking(move || {
                // We need a tokio handle to call async scan_file()
                tokio::runtime::Handle::current().block_on(async {
                    scan_one_file(event, &clamscan, &config, &result_tx).await;
                });
            });
        }

        info!("ScanEngine: event channel closed — shutting down");
        Ok(())
    }

    /// Scan a single file on demand and return the ScanResult.
    ///
    /// This is the **on-demand API** used by:
    /// - Dashboard "Scan File" command (IPC)
    /// - Scheduler (quick/full scan)
    /// - Integration tests
    ///
    /// Does not require the event channel. Returns immediately with the result.
    ///
    /// # Arguments
    /// - `file_path` — path to the file to scan
    /// - `config`    — scanner configuration
    ///
    /// # Returns
    /// A `ScanResult` with the verdict, timing, and metadata.
    pub async fn scan_file_now(
        file_path: &Path,
        config:    &AgentConfig,
    ) -> ScanResult {
        let clamscan = find_clamscan(&config.scanner);

        let (verdict, _raw) = if let Some(ref bin) = clamscan {
            let start = Instant::now();
            let result = scan_file(bin, file_path, &config.scanner).await;
            let _ = start; // timing captured inside scan_one_file
            result
        } else {
            (
                ScanVerdict::Error("CyberFence Engine not installed".to_string()),
                String::new(),
            )
        };

        let size_bytes = std::fs::metadata(file_path).ok().map(|m| m.len());

        ScanResult {
            id:                   Uuid::new_v4(),
            scanned_at:           Utc::now(),
            path:                 file_path.to_path_buf(),
            size_bytes,
            triggered_by_event:   None, // on-demand, not triggered by a file event
            duration_ms:          0,    // not tracked in this path (use spawn_blocking for timing)
            verdict,
            definitions_version:  None,
        }
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Scan a single file, build a ScanResult, and send it to the result channel.
async fn scan_one_file(
    event:        FileEvent,
    clamscan_bin: &Path,
    config:       &AgentConfig,
    result_tx:    &mpsc::Sender<ScanResult>,
) {
    let scan_cfg = &config.scanner;
    let path     = &event.path;

    // Final size check: file may have grown since the event was emitted
    if let Some(size_bytes) = event.size_bytes {
        let max_bytes = scan_cfg.max_file_size_mb * 1024 * 1024;
        if size_bytes > max_bytes {
            let result = build_result(
                &event,
                ScanVerdict::Skipped(format!(
                    "File too large: {} MB > {} MB limit",
                    size_bytes / 1024 / 1024,
                    scan_cfg.max_file_size_mb,
                )),
                0,
            );
            send_result(result, result_tx).await;
            return;
        }
    }

    // Run the scan
    let start                   = Instant::now();
    let (verdict, _raw_output)  = scan_file(clamscan_bin, path, scan_cfg).await;
    let duration_ms             = start.elapsed().as_millis() as u64;

    // Structured log at the appropriate level
    log_verdict(path, &verdict, duration_ms);

    let result = build_result(&event, verdict, duration_ms);
    send_result(result, result_tx).await;
}

/// Build a `ScanResult` from a `FileEvent` and verdict.
fn build_result(event: &FileEvent, verdict: ScanVerdict, duration_ms: u64) -> ScanResult {
    ScanResult {
        id:                   Uuid::new_v4(),
        scanned_at:           Utc::now(),
        path:                 event.path.clone(),
        size_bytes:           event.size_bytes,
        triggered_by_event:   Some(event.id),
        duration_ms,
        verdict,
        definitions_version:  None, // populated in Phase 3 via version check
    }
}

/// Send a ScanResult to the result channel (non-blocking).
async fn send_result(result: ScanResult, tx: &mpsc::Sender<ScanResult>) {
    match tx.try_send(result) {
        Ok(_)  => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            warn!("ScanResult channel full — result dropped. Consider increasing ring_buffer_cap.");
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            // Consumer has shut down — this is expected during shutdown
        }
    }
}

/// Log the scan verdict at the appropriate tracing level.
fn log_verdict(path: &Path, verdict: &ScanVerdict, duration_ms: u64) {
    match verdict {
        ScanVerdict::Infected(name) => {
            error!(
                verdict     = "INFECTED",
                path        = %path.display(),
                virus       = %name,
                duration_ms,
                "🚨 MALWARE DETECTED — file will be quarantined"
            );
        }
        ScanVerdict::Suspicious(name) => {
            warn!(
                verdict     = "SUSPICIOUS",
                path        = %path.display(),
                rule        = %name,
                duration_ms,
                "⚠️  Suspicious file — heuristic match"
            );
        }
        ScanVerdict::Clean => {
            debug!(
                verdict     = "CLEAN",
                path        = %path.display(),
                duration_ms,
                "File scanned — clean"
            );
        }
        ScanVerdict::Error(msg) => {
            warn!(
                verdict     = "ERROR",
                path        = %path.display(),
                error       = %msg,
                duration_ms,
                "Scan error"
            );
        }
        ScanVerdict::Skipped(reason) => {
            debug!(
                verdict     = "SKIPPED",
                path        = %path.display(),
                reason      = %reason,
                "Scan skipped"
            );
        }
    }
}

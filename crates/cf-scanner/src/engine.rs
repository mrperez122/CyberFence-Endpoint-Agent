//! ScanEngine — on-access scanner that consumes FileEvents from the monitor.
//!
//! # How scanning is triggered
//!
//! The monitor produces `FileEvent` values on a tokio MPSC channel.
//! ScanEngine reads from a clone of that channel (via EventFanout),
//! filters out non-scannable events, and dispatches each file to a
//! `tokio::task::spawn_blocking` call that runs `clamscan`.
//!
//! # How results are handled
//!
//! Each scan produces a `ScanResult` which is:
//! 1. Logged immediately via the `result_tx` channel → cf-logger
//! 2. Forwarded to the cf-broker (Phase 3) for quarantine decisions
//!
//! Threat events are logged at WARN/ERROR level; clean files at DEBUG.

use std::path::PathBuf;
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

/// On-access scanning engine.
///
/// Receives `FileEvent` values from cf-monitor and scans each scannable file.
pub struct ScanEngine {
    config:    Arc<AgentConfig>,
    event_rx:  mpsc::Receiver<FileEvent>,
    result_tx: mpsc::Sender<ScanResult>,
    clamscan:  Option<PathBuf>,
}

impl ScanEngine {
    /// Create a new ScanEngine.
    ///
    /// - `event_rx` receives FileEvents from the monitor pipeline.
    /// - `result_tx` is where ScanResults are sent for logging/acting on.
    pub fn new(
        config: AgentConfig,
        event_rx: mpsc::Receiver<FileEvent>,
        result_tx: mpsc::Sender<ScanResult>,
    ) -> Self {
        let clamscan = find_clamscan(&config.scanner);

        if config.scanner.enabled {
            match &clamscan {
                Some(p) => info!(path = %p.display(), "ClamAV binary found"),
                None => warn!(
                    "ClamAV (clamscan) not found on this system. \
                     Scanning will be disabled. Install ClamAV and ensure \
                     it's in PATH or set scanner.clamscan_path in config.toml"
                ),
            }
        }

        Self {
            config: Arc::new(config),
            event_rx,
            result_tx,
            clamscan,
        }
    }

    /// Run the scan engine loop.
    /// Consumes FileEvents until the channel is closed.
    pub async fn run(mut self) -> Result<()> {
        if !self.config.scanner.enabled {
            info!("Scanning is disabled in config — ScanEngine exiting");
            // Drain the channel so the monitor doesn't block
            while self.event_rx.recv().await.is_some() {}
            return Ok(());
        }

        let Some(clamscan_path) = self.clamscan else {
            error!("ClamAV not found — ScanEngine cannot start. Draining event channel.");
            while self.event_rx.recv().await.is_some() {}
            return Ok(());
        };

        info!("ScanEngine started — waiting for file events");

        while let Some(event) = self.event_rx.recv().await {
            // Only scan files that are flagged as ready
            if !event.is_scannable() {
                debug!(
                    path = %event.path.display(),
                    readiness = ?event.scan_readiness,
                    "Skipping non-scannable event"
                );
                continue;
            }

            let config      = Arc::clone(&self.config);
            let result_tx   = self.result_tx.clone();
            let clamscan    = clamscan_path.clone();

            // Run the scan in a blocking thread (clamscan is synchronous).
            tokio::task::spawn_blocking(move || {
                // We need a tokio handle to call async scan_file
                tokio::runtime::Handle::current().block_on(async {
                    scan_one_file(event, &clamscan, &config, &result_tx).await;
                });
            });
        }

        info!("ScanEngine: event channel closed — shutting down");
        Ok(())
    }
}

/// Scan a single file and emit a ScanResult.
async fn scan_one_file(
    event:        FileEvent,
    clamscan_bin: &PathBuf,
    config:       &AgentConfig,
    result_tx:    &mpsc::Sender<ScanResult>,
) {
    let path      = &event.path;
    let scan_cfg  = &config.scanner;

    // Final size check (file may have grown after the event was emitted)
    if let Some(size) = &event.size_bytes {
        let max_bytes = scan_cfg.max_file_size_mb * 1024 * 1024;
        if *size > max_bytes {
            let result = make_result(
                &event,
                ScanVerdict::Skipped(format!(
                    "File too large ({} MB > {} MB limit)",
                    size / 1024 / 1024,
                    scan_cfg.max_file_size_mb
                )),
                0,
            );
            emit_result(result, result_tx).await;
            return;
        }
    }

    let start = Instant::now();
    let (verdict, raw_output) = scan_file(clamscan_bin, path, scan_cfg).await;
    let duration_ms = start.elapsed().as_millis() as u64;

    log_verdict(path, &verdict, duration_ms, &raw_output);

    let result = make_result(&event, verdict, duration_ms);
    emit_result(result, result_tx).await;
}

/// Build a ScanResult from an event + verdict.
fn make_result(event: &FileEvent, verdict: ScanVerdict, duration_ms: u64) -> ScanResult {
    ScanResult {
        id:                    Uuid::new_v4(),
        scanned_at:            Utc::now(),
        path:                  event.path.clone(),
        size_bytes:            event.size_bytes,
        triggered_by_event:    Some(event.id),
        duration_ms,
        verdict,
        definitions_version:   None, // populated in Phase 3
    }
}

/// Emit a ScanResult to the result channel (non-blocking).
async fn emit_result(result: ScanResult, tx: &mpsc::Sender<ScanResult>) {
    match tx.try_send(result) {
        Ok(_) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            warn!("ScanResult channel full — result dropped");
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {}
    }
}

/// Log the scan verdict at the appropriate level.
fn log_verdict(path: &PathBuf, verdict: &ScanVerdict, duration_ms: u64, _raw: &str) {
    match verdict {
        ScanVerdict::Infected(name) => {
            error!(
                verdict  = "INFECTED",
                path     = %path.display(),
                virus    = %name,
                duration_ms,
                "🚨 MALWARE DETECTED"
            );
        }
        ScanVerdict::Suspicious(name) => {
            warn!(
                verdict  = "SUSPICIOUS",
                path     = %path.display(),
                rule     = %name,
                duration_ms,
                "⚠️  Suspicious file detected"
            );
        }
        ScanVerdict::Clean => {
            debug!(
                verdict  = "CLEAN",
                path     = %path.display(),
                duration_ms,
                "File clean"
            );
        }
        ScanVerdict::Error(msg) => {
            warn!(
                verdict  = "ERROR",
                path     = %path.display(),
                error    = %msg,
                duration_ms,
                "Scan error"
            );
        }
        ScanVerdict::Skipped(reason) => {
            debug!(
                verdict  = "SKIPPED",
                path     = %path.display(),
                reason   = %reason,
                "File skipped"
            );
        }
    }
}

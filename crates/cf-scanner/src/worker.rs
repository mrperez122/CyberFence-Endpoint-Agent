//! ScanResultWorker — consumes ScanResults and dispatches to logger/broker.
//!
//! This is the output side of the scanner pipeline. It receives `ScanResult`
//! values and routes them:
//!   - All results → cf-logger (structured JSONL audit record)
//!   - Threats only → future cf-broker (Phase 3 quarantine decisions)

use anyhow::Result;
use cf_common::scan::{ScanResult, ScanSummary, ScanVerdict};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// Consumes ScanResults and ScanSummaries, logging each one.
pub struct ScanResultWorker {
    result_rx:  mpsc::Receiver<ScanResult>,
    summary_rx: mpsc::Receiver<ScanSummary>,
}

impl ScanResultWorker {
    pub fn new(
        result_rx:  mpsc::Receiver<ScanResult>,
        summary_rx: mpsc::Receiver<ScanSummary>,
    ) -> Self {
        Self { result_rx, summary_rx }
    }

    /// Run the result processing loop.
    pub async fn run(mut self) -> Result<()> {
        info!("ScanResultWorker started");

        loop {
            tokio::select! {
                // Process incoming scan results
                result = self.result_rx.recv() => {
                    match result {
                        Some(r) => self.handle_result(r),
                        None    => {
                            info!("ScanResult channel closed");
                            break;
                        }
                    }
                }

                // Process scan summaries
                summary = self.summary_rx.recv() => {
                    match summary {
                        Some(s) => self.handle_summary(s),
                        None    => {} // summary channel closing is non-fatal
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_result(&self, result: ScanResult) {
        let is_threat = result.requires_action();

        // Structured log — this is what the UI's Event Log reads
        if is_threat {
            match &result.verdict {
                ScanVerdict::Infected(name) => {
                    error!(
                        target: "SCAN_RESULT",
                        result_id    = %result.id,
                        verdict      = "INFECTED",
                        virus        = %name,
                        path         = %result.path.display(),
                        size_bytes   = ?result.size_bytes,
                        duration_ms  = result.duration_ms,
                        severity     = %result.severity(),
                        "MALWARE DETECTED — immediate action required"
                    );
                }
                ScanVerdict::Suspicious(rule) => {
                    warn!(
                        target: "SCAN_RESULT",
                        result_id    = %result.id,
                        verdict      = "SUSPICIOUS",
                        rule         = %rule,
                        path         = %result.path.display(),
                        size_bytes   = ?result.size_bytes,
                        duration_ms  = result.duration_ms,
                        severity     = %result.severity(),
                        "Suspicious file detected"
                    );
                }
                _ => {}
            }

            // Phase 3: send to cf-broker for quarantine decision
            // broker_tx.send(ThreatAlert::from(&result)).await?;

        } else {
            // Clean / skipped / error — log at debug level only
            tracing::debug!(
                target: "SCAN_RESULT",
                result_id  = %result.id,
                verdict    = %result.verdict.label(),
                path       = %result.path.display(),
                duration_ms = result.duration_ms,
                "Scan result"
            );
        }
    }

    fn handle_summary(&self, summary: ScanSummary) {
        info!(
            target: "SCAN_SUMMARY",
            job_id        = %summary.job_id,
            scan_type     = %summary.scan_type,
            files_scanned = summary.files_scanned,
            infected      = summary.infected,
            suspicious    = summary.suspicious,
            errors        = summary.errors,
            duration_secs = summary.duration_secs(),
            cancelled     = summary.cancelled,
            "Scan job complete"
        );
    }
}

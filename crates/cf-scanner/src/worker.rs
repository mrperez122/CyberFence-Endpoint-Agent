//! ScanResultWorker — consumes ScanResults, logs them, and acts on threats.
//!
//! This is the output side of the scanner pipeline. It receives `ScanResult`
//! values and:
//!
//! 1. Writes every result to the structured scan log (`scan_logger`)
//! 2. For INFECTED files: triggers quarantine
//! 3. For SUSPICIOUS files: logs at WARN level (no auto-quarantine)
//! 4. Emits threat events for the UI (Phase 3: via named pipe)
//! 5. Logs scan summary statistics

use anyhow::Result;
use cf_common::scan::{ScanResult, ScanSummary, ScanVerdict};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::quarantine;
use crate::scan_logger::ScanLogger;

/// Consumes ScanResults and ScanSummaries, logs each one, acts on threats.
pub struct ScanResultWorker {
    result_rx:  mpsc::Receiver<ScanResult>,
    summary_rx: mpsc::Receiver<ScanSummary>,
    logger:     ScanLogger,
}

impl ScanResultWorker {
    pub fn new(
        result_rx:  mpsc::Receiver<ScanResult>,
        summary_rx: mpsc::Receiver<ScanSummary>,
    ) -> Self {
        Self {
            result_rx,
            summary_rx,
            logger: ScanLogger::with_default_dir(),
        }
    }

    /// Run the result processing loop.
    pub async fn run(mut self) -> Result<()> {
        info!("ScanResultWorker started");

        let mut total_scanned:  u64 = 0;
        let mut total_threats:  u32 = 0;
        let mut total_errors:   u32 = 0;

        loop {
            tokio::select! {
                result = self.result_rx.recv() => {
                    match result {
                        Some(r) => {
                            total_scanned += 1;
                            if r.verdict.is_threat()             { total_threats += 1; }
                            if matches!(r.verdict, ScanVerdict::Error(_)) { total_errors += 1; }
                            self.handle_result(r);
                        }
                        None => {
                            info!(
                                total_scanned,
                                total_threats,
                                total_errors,
                                "ScanResultWorker: result channel closed"
                            );
                            break;
                        }
                    }
                }

                summary = self.summary_rx.recv() => {
                    if let Some(s) = summary {
                        self.handle_summary(&s);
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_result(&self, result: ScanResult) {
        let action = determine_action(&result.verdict);

        // Always write to the structured scan log
        if let Err(e) = self.logger.write(&result, action) {
            warn!(error = %e, "Failed to write to scan log");
        }

        // Act based on verdict
        match &result.verdict {
            ScanVerdict::Infected(virus_name) => {
                error!(
                    target:       "SCAN_RESULT",
                    result_id     = %result.id,
                    verdict       = "INFECTED",
                    virus         = %virus_name,
                    path          = %result.path.display(),
                    size_bytes    = ?result.size_bytes,
                    duration_ms   = result.duration_ms,
                    severity      = %result.severity(),
                    action        = action,
                    "MALWARE DETECTED"
                );

                // Attempt quarantine
                match quarantine::quarantine_file(&result.path, virus_name) {
                    Ok(record) => {
                        info!(
                            vault = %record.vault_path.display(),
                            "File quarantined successfully"
                        );
                        // Phase 3: send ThreatAlert to UI via named pipe
                        // broker_tx.send(ThreatAlert::from(&result, &record)).ok();
                    }
                    Err(e) => {
                        error!(
                            error = %e,
                            path  = %result.path.display(),
                            "Failed to quarantine infected file — file may still be accessible"
                        );
                    }
                }
            }

            ScanVerdict::Suspicious(rule_name) => {
                warn!(
                    target:       "SCAN_RESULT",
                    result_id     = %result.id,
                    verdict       = "SUSPICIOUS",
                    rule          = %rule_name,
                    path          = %result.path.display(),
                    size_bytes    = ?result.size_bytes,
                    duration_ms   = result.duration_ms,
                    severity      = %result.severity(),
                    action        = action,
                    "Suspicious file detected"
                );
                // Suspicious files are logged but not auto-quarantined.
                // The user can review in the dashboard and quarantine manually.
            }

            ScanVerdict::Error(msg) => {
                warn!(
                    target:       "SCAN_RESULT",
                    result_id     = %result.id,
                    verdict       = "ERROR",
                    error         = %msg,
                    path          = %result.path.display(),
                    duration_ms   = result.duration_ms,
                    "Scan error"
                );
            }

            ScanVerdict::Clean | ScanVerdict::Skipped(_) => {
                debug!(
                    target:       "SCAN_RESULT",
                    result_id     = %result.id,
                    verdict       = %result.verdict.label(),
                    path          = %result.path.display(),
                    duration_ms   = result.duration_ms,
                    "Scan result"
                );
            }
        }
    }

    fn handle_summary(&self, summary: &ScanSummary) {
        info!(
            target:         "SCAN_SUMMARY",
            job_id          = %summary.job_id,
            scan_type       = %summary.scan_type,
            files_scanned   = summary.files_scanned,
            infected        = summary.infected,
            suspicious      = summary.suspicious,
            errors          = summary.errors,
            duration_secs   = summary.duration_secs(),
            cancelled       = summary.cancelled,
            "Scan job complete"
        );
    }
}

/// Determine what action was taken for logging purposes.
fn determine_action(verdict: &ScanVerdict) -> &'static str {
    match verdict {
        ScanVerdict::Infected(_)   => "QUARANTINED",
        ScanVerdict::Suspicious(_) => "LOGGED",
        ScanVerdict::Clean         => "LOGGED",
        ScanVerdict::Error(_)      => "LOGGED",
        ScanVerdict::Skipped(_)    => "SKIPPED",
    }
}

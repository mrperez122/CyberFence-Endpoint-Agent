//! Full and quick system scan implementation.
//!
//! This module handles scheduled or manually triggered scans across
//! entire directories — as opposed to the on-access scanner in engine.rs
//! which reacts to individual file events.
//!
//! # How a full scan works
//!
//! 1. Walk all configured paths recursively with `walkdir`
//! 2. Filter files by size, extension exclusions, and accessibility
//! 3. Feed them into a parallel worker pool (N = CPU cores / 2)
//! 4. Emit ScanProgress events every 100 files
//! 5. Emit a ScanSummary when complete

use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    Arc,
};
use std::time::Instant;

use anyhow::Result;
use cf_common::scan::{ScanProgress, ScanResult, ScanSummary, ScanType, ScanVerdict};
use cf_config::AgentConfig;
use chrono::Utc;
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;
use walkdir::WalkDir;

use crate::clamav::{find_clamscan, scan_file};

/// Full or quick system scanner.
pub struct FullScanner {
    config:      Arc<AgentConfig>,
    result_tx:   mpsc::Sender<ScanResult>,
    progress_tx: mpsc::Sender<ScanProgress>,
    summary_tx:  mpsc::Sender<ScanSummary>,
    cancel:      Arc<AtomicBool>,
}

impl FullScanner {
    pub fn new(
        config:      AgentConfig,
        result_tx:   mpsc::Sender<ScanResult>,
        progress_tx: mpsc::Sender<ScanProgress>,
        summary_tx:  mpsc::Sender<ScanSummary>,
        cancel:      Arc<AtomicBool>,
    ) -> Self {
        Self {
            config: Arc::new(config),
            result_tx,
            progress_tx,
            summary_tx,
            cancel,
        }
    }

    /// Run a quick scan of high-risk directories (Downloads, Desktop, Temp, Startup).
    pub async fn run_quick_scan(&self) -> Result<()> {
        let paths = self.config.watch_dirs();
        info!(dirs = ?paths, "Starting quick scan");
        self.scan_paths(paths, ScanType::QuickScan).await
    }

    /// Run a full scan of all configured paths.
    pub async fn run_full_scan(&self) -> Result<()> {
        let mut paths = self.config.scanner.full_scan_paths.clone();
        if paths.is_empty() {
            // Fallback to watch dirs if no explicit full scan paths set
            paths = self.config.watch_dirs();
        }
        info!(dirs = ?paths, "Starting full scan");
        self.scan_paths(paths, ScanType::FullScan).await
    }

    /// Core scan runner — walks directories and scans each file.
    async fn scan_paths(&self, paths: Vec<PathBuf>, scan_type: ScanType) -> Result<()> {
        let Some(clamscan_bin) = find_clamscan(&self.config.scanner) else {
            warn!("ClamAV not found — cannot run {} scan", scan_type);
            return Ok(());
        };

        let job_id     = Uuid::new_v4();
        let started_at = Utc::now();
        let scan_cfg   = &self.config.scanner;

        // ── Step 1: collect all files to scan ────────────────────────────────
        let all_files: Vec<PathBuf> = paths
            .iter()
            .flat_map(|root| {
                WalkDir::new(root)
                    .follow_links(false)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().is_file())
                    .map(|e| e.path().to_path_buf())
                    .filter(|p| should_scan_file(p, scan_cfg))
            })
            .collect();

        let total = all_files.len() as u64;
        info!(
            job_id = %job_id,
            total_files = total,
            scan_type   = %scan_type,
            "Full scan started"
        );

        // ── Step 2: shared counters ───────────────────────────────────────────
        let scanned   = Arc::new(AtomicU64::new(0));
        let infected  = Arc::new(AtomicU32::new(0));
        let suspicious= Arc::new(AtomicU32::new(0));
        let errors    = Arc::new(AtomicU32::new(0));

        // ── Step 3: scan each file with concurrency ───────────────────────────
        let worker_count = if scan_cfg.worker_threads == 0 {
            std::cmp::max(1, num_cpus() / 2)
        } else {
            scan_cfg.worker_threads
        };

        let semaphore = Arc::new(tokio::sync::Semaphore::new(worker_count));
        let mut handles = Vec::with_capacity(all_files.len());

        for file_path in all_files {
            // Check cancellation flag
            if self.cancel.load(Ordering::Relaxed) {
                info!(job_id = %job_id, "Scan cancelled by user");
                break;
            }

            let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();

            let clamscan  = clamscan_bin.clone();
            let config    = Arc::clone(&self.config);
            let result_tx = self.result_tx.clone();
            let scanned_c = Arc::clone(&scanned);
            let infected_c= Arc::clone(&infected);
            let susp_c    = Arc::clone(&suspicious);
            let errors_c  = Arc::clone(&errors);
            let prog_tx   = self.progress_tx.clone();
            let jid       = job_id;
            let total_c   = total;

            handles.push(tokio::spawn(async move {
                let _permit = permit; // released when handle drops

                let start = Instant::now();
                let size  = std::fs::metadata(&file_path).ok().map(|m| m.len());
                let (verdict, _) = scan_file(&clamscan, &file_path, &config.scanner).await;
                let ms    = start.elapsed().as_millis() as u64;

                // Update counters
                match &verdict {
                    ScanVerdict::Infected(_)   => { infected_c.fetch_add(1, Ordering::Relaxed); }
                    ScanVerdict::Suspicious(_) => { susp_c.fetch_add(1, Ordering::Relaxed); }
                    ScanVerdict::Error(_)      => { errors_c.fetch_add(1, Ordering::Relaxed); }
                    _ => {}
                }

                let n = scanned_c.fetch_add(1, Ordering::Relaxed) + 1;

                // Emit progress every 100 files
                if n % 100 == 0 || n == total_c {
                    let pct = ((n as f64 / total_c as f64) * 100.0).min(100.0) as u8;
                    let _ = prog_tx.try_send(ScanProgress {
                        job_id:        jid,
                        total_files:   total_c,
                        scanned_files: n,
                        threats_found: infected_c.load(Ordering::Relaxed)
                                     + susp_c.load(Ordering::Relaxed),
                        current_file:  Some(file_path.clone()),
                        percent:       pct,
                    });
                }

                // Emit result
                let result = ScanResult {
                    id:                 Uuid::new_v4(),
                    scanned_at:         Utc::now(),
                    path:               file_path,
                    size_bytes:         size,
                    triggered_by_event: None,
                    duration_ms:        ms,
                    verdict,
                    definitions_version: None,
                };
                let _ = result_tx.try_send(result);
            }));
        }

        // Await all workers
        for h in handles {
            let _ = h.await;
        }

        let cancelled   = self.cancel.load(Ordering::Relaxed);
        let files_done  = scanned.load(Ordering::Relaxed);
        let inf         = infected.load(Ordering::Relaxed);
        let susp        = suspicious.load(Ordering::Relaxed);
        let err         = errors.load(Ordering::Relaxed);
        let completed_at = Utc::now();

        info!(
            job_id      = %job_id,
            files_scanned = files_done,
            infected    = inf,
            suspicious  = susp,
            errors      = err,
            cancelled   = cancelled,
            duration_secs = (completed_at - started_at).num_seconds(),
            "Scan complete"
        );

        let _ = self.summary_tx.try_send(ScanSummary {
            job_id,
            scan_type,
            started_at,
            completed_at,
            files_scanned: files_done,
            infected:      inf,
            suspicious:    susp,
            errors:        err,
            cancelled,
        });

        Ok(())
    }
}

/// Returns true if this file should be included in a full/quick scan.
fn should_scan_file(path: &PathBuf, config: &cf_config::ScannerConfig) -> bool {
    // Skip excluded extensions
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_lowercase();
        let excluded  = ["log", "tmp", "db-wal", "db-shm", "part", "crdownload"];
        if excluded.contains(&ext_lower.as_str()) {
            return false;
        }
    }

    // Skip files too large
    if let Ok(meta) = std::fs::metadata(path) {
        let max_bytes = config.max_file_size_mb * 1024 * 1024;
        if meta.len() > max_bytes {
            return false;
        }
    } else {
        // Can't read metadata → skip
        return false;
    }

    true
}

/// Platform-specific CPU count.
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
}

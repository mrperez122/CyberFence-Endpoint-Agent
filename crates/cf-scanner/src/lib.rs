//! cf-scanner — Malware scanning engine for the CyberFence Endpoint Agent.
//!
//! # What this crate does
//!
//! 1. **On-access scanning** — `ScanEngine` consumes `FileEvent` values from
//!    cf-monitor and scans each file the moment it appears.
//!
//! 2. **On-demand scanning** — `ScanEngine::scan_file_now()` lets any caller
//!    (dashboard, IPC command, scheduler) request a synchronous file scan.
//!
//! 3. **Quarantine** — `quarantine::quarantine_file()` AES-256-GCM encrypts an
//!    infected file and moves it to the vault so it cannot be executed.
//!
//! 4. **Result logging** — `scan_logger::ScanLogger` writes one structured JSON
//!    line per scan to a dedicated `scans-YYYY-MM-DD.jsonl` file, separate from
//!    the main agent log.
//!
//! # How the monitoring service calls this scanner
//!
//! ```text
//! cf-monitor::FileMonitor
//!     ↓  FileEvent  (via tokio MPSC channel)
//! EventFanout  (agent/src/main.rs)
//!     └──► scanner_tx  ──► ScanEngine::run()
//!                               ↓  for each is_scannable() event:
//!                               ↓  tokio::task::spawn_blocking(clamscan subprocess)
//!                               ↓  ScanResult built
//!                               ↓  result_tx.send(ScanResult)
//!                                       ↓
//!                          ScanResultWorker::run()
//!                               ↓  log to scan log file
//!                               ↓  if threat: quarantine + OS notification stub
//! ```
//!
//! # ClamAV installation
//!
//! ## Windows (required for on-access scanning)
//! ```text
//! choco install clamav -y          (adds clamscan.exe to Program Files\ClamAV)
//! freshclam.exe                    (downloads ~280 MB virus definitions)
//! ```
//! Alternatively download from https://www.clamav.net/downloads
//!
//! ## macOS
//! ```bash
//! brew install clamav
//! cp /opt/homebrew/etc/clamav/freshclam.conf.sample \
//!    /opt/homebrew/etc/clamav/freshclam.conf
//! # Remove the "Example" line, then:
//! freshclam
//! ```
//!
//! ## Graceful degradation
//!
//! If `clamscan` is not found on the system, `ScanEngine` logs a WARNING
//! and enters **monitor-only mode**: file events continue to be logged by
//! cf-logger but no scanning occurs. The agent never crashes due to a missing
//! ClamAV installation.

pub mod clamav;
pub mod engine;
pub mod full_scan;
pub mod quarantine;
pub mod scan_logger;
pub mod worker;

pub use engine::ScanEngine;
pub use full_scan::FullScanner;

//! cf-agent — CyberFence Endpoint Protection Agent
//!
//! # Startup sequence (Phase 2 — with scanner)
//!
//! 1. Load config from disk (or defaults)
//! 2. Initialize tracing subscriber (file + stdout)
//! 3. Resolve watch directories
//! 4. Build channels:
//!      monitor_tx  → (FileEvent)  → [EventFanout]
//!      EventFanout → logger_rx    → EventLogger
//!      EventFanout → scanner_rx   → ScanEngine
//!      scanner     → result_rx    → ScanResultWorker
//! 5. Spawn all tasks
//! 6. Wait for Ctrl-C → graceful shutdown
//!
//! # Data flow
//!
//! ```text
//! OS kernel
//!   ↓ inotify / ReadDirectoryChangesW / FSEvents
//! FileMonitor (cf-monitor)
//!   ↓ FileEvent  [tokio MPSC]
//! EventFanout
//!   ├─→ EventLogger  (cf-logger)  — JSONL audit trail
//!   └─→ ScanEngine   (cf-scanner) — ClamAV on-access scan
//!                         ↓ ScanResult  [tokio MPSC]
//!                     ScanResultWorker — log threats, Phase 3 quarantine
//! ```

use anyhow::Result;
use cf_config::AgentConfig;
use cf_logger::{init_subscriber, EventLogger};
use cf_monitor::FileMonitor;
use cf_scanner::{
    ScanEngine,
    worker::ScanResultWorker,
};
use tokio::sync::mpsc;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    // ── 1. Load configuration ─────────────────────────────────────────────────
    let config = AgentConfig::load_default().unwrap_or_else(|e| {
        eprintln!("[CyberFence] Config load failed: {} — using defaults", e);
        AgentConfig::default()
    });

    // ── 2. Initialize logging ─────────────────────────────────────────────────
    if let Err(e) = init_subscriber(&config) {
        eprintln!("[CyberFence] Logger init failed: {}", e);
    }

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "CyberFence Endpoint Agent starting"
    );

    let watch_dirs = config.watch_dirs();
    info!(dirs = ?watch_dirs, "Resolved watch directories");

    // ── 3. Build event channels ───────────────────────────────────────────────
    let buf = config.monitor.ring_buffer_cap;

    // Monitor → fanout (single producer)
    let (monitor_tx, monitor_rx) = mpsc::channel(buf);

    // Fanout → EventLogger
    let (logger_tx,  logger_rx)  = mpsc::channel::<cf_common::FileEvent>(buf);

    // Fanout → ScanEngine
    let (scanner_tx, scanner_rx) = mpsc::channel::<cf_common::FileEvent>(buf);

    // ScanEngine → ScanResultWorker
    let (result_tx,  result_rx)  = mpsc::channel::<cf_common::ScanResult>(buf);

    // Progress / summary channels (consumed by ScanResultWorker)
    let (_progress_tx, _progress_rx) = mpsc::channel::<cf_common::ScanProgress>(64); // UI will use these in Phase 3
    let (_summary_tx,  summary_rx)   = mpsc::channel::<cf_common::ScanSummary>(16);

    // ── 4. Spawn EventFanout ──────────────────────────────────────────────────
    //   Bridges the single monitor channel to two downstream consumers.
    let fanout_handle = tokio::spawn(async move {
        let mut rx: mpsc::Receiver<cf_common::FileEvent> = monitor_rx;
        while let Some(event) = rx.recv().await {
            // Send to logger (non-blocking — drop on full)
            let _ = logger_tx.try_send(event.clone());
            // Send to scanner (non-blocking — drop on full)
            let _ = scanner_tx.try_send(event);
        }
        info!("EventFanout: monitor channel closed");
    });

    // ── 5. Spawn FileMonitor ──────────────────────────────────────────────────
    let monitor = FileMonitor::new(config.clone(), monitor_tx);
    let monitor_handle = tokio::spawn(async move {
        if let Err(e) = monitor.run().await {
            error!("FileMonitor exited with error: {}", e);
        }
    });

    // ── 6. Spawn EventLogger ──────────────────────────────────────────────────
    let logger = EventLogger::new(logger_rx);
    let logger_handle = tokio::spawn(async move {
        if let Err(e) = logger.run().await {
            error!("EventLogger exited with error: {}", e);
        }
    });

    // ── 7. Spawn ScanEngine (on-access) ──────────────────────────────────────
    let scan_engine = ScanEngine::new(config.clone(), scanner_rx, result_tx);
    let scanner_handle = tokio::spawn(async move {
        if let Err(e) = scan_engine.run().await {
            error!("ScanEngine exited with error: {}", e);
        }
    });

    // ── 8. Spawn ScanResultWorker ─────────────────────────────────────────────
    let result_worker = ScanResultWorker::new(result_rx, summary_rx);
    let result_handle = tokio::spawn(async move {
        if let Err(e) = result_worker.run().await {
            error!("ScanResultWorker exited with error: {}", e);
        }
    });

    // ── 9. Optional: trigger a quick scan on startup ──────────────────────────
    //   Uncomment to always run a quick scan when the agent starts.
    //   In Phase 3 this will be managed by the scheduler.
    //
    // let cancel = Arc::new(AtomicBool::new(false));
    // let full_scanner = cf_scanner::FullScanner::new(
    //     config.clone(), result_tx2.clone(), progress_tx.clone(), summary_tx.clone(), cancel
    // );
    // tokio::spawn(async move { full_scanner.run_quick_scan().await });

    info!("CyberFence agent fully started — press Ctrl-C to stop");
    info!("Monitoring: Downloads, Desktop, Documents (+ configured dirs)");
    info!("Scanning:   {} (ClamAV on-access)",
        if config.scanner.enabled { "ENABLED" } else { "DISABLED" }
    );

    // ── 10. Wait for shutdown signal ──────────────────────────────────────────
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Ctrl-C received — initiating graceful shutdown");
        }
        _ = monitor_handle => {
            error!("FileMonitor task exited unexpectedly");
        }
        _ = logger_handle => {
            error!("EventLogger task exited unexpectedly");
        }
        _ = scanner_handle => {
            error!("ScanEngine task exited unexpectedly");
        }
        _ = result_handle => {
            error!("ScanResultWorker task exited unexpectedly");
        }
        _ = fanout_handle => {
            error!("EventFanout task exited unexpectedly");
        }
    }

    info!("CyberFence agent stopped");
    Ok(())
}

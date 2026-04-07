//! cf-agent — CyberFence Endpoint Protection Agent
//!
//! # Dual-mode binary
//!
//! This binary runs in two distinct modes depending on how it's launched:
//!
//! | Mode           | How to trigger                        | Use case              |
//! |----------------|---------------------------------------|-----------------------|
//! | Console mode   | `cargo run` or double-click .exe      | Development, testing  |
//! | Service mode   | Started by Windows SCM (`sc start`)   | Production deployment |
//!
//! The binary detects which mode it's in by attempting to connect to the
//! Service Control Manager. If the SCM connection fails with error 1063
//! ("not a service"), it falls through to console mode.
//!
//! # Event pipeline (Phase 1–2)
//!
//! ```text
//! OS kernel (ReadDirectoryChangesW)
//!     ↓
//! cf-monitor::FileMonitor
//!     ↓  FileEvent  [tokio MPSC, cap=2000]
//! EventFanout
//!     ├──► cf-logger::EventLogger   → JSONL audit log
//!     └──► cf-scanner::ScanEngine  → CyberFence Engine (Phase 2)
//!                    ↓  ScanResult
//!          cf-scanner::ScanResultWorker → log threats
//! ```
//!
//! # Phase 3 additions (not yet implemented)
//!
//! - Named pipe IPC server (`ipc_server.rs`) for Tauri UI connection
//! - CrowdSec threat intelligence enrichment

// Suppress the Windows console window in release builds
#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]

use anyhow::Result;
use cf_config::AgentConfig;
use cf_logger::{init_subscriber, EventLogger};
use cf_monitor::FileMonitor;
use cf_scanner::{worker::ScanResultWorker, ScanEngine};
use tokio::sync::mpsc;
use tracing::{error, info};

// Platform-specific service module (Windows only)
#[cfg(target_os = "windows")]
mod service;

// ── Entry point ────────────────────────────────────────────────────────────────

fn main() {
    #[cfg(target_os = "windows")]
    {
        // Try to connect to the Windows SCM.
        // If this succeeds, the SCM has taken over and will call our service_main.
        // We do NOT call run_agent() here — the service module handles that.
        match service::try_start_as_service() {
            Ok(true)  => return, // service dispatcher took over — we're done in this thread
            Ok(false) => {}      // not running as service — fall through to console mode
            Err(e)    => {
                eprintln!("[CyberFence] Service dispatcher error: {} — falling back to console mode", e);
            }
        }
    }

    // Console mode: build a tokio runtime and run the agent directly.
    // This is the path used in development and testing.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("cf-agent-worker")
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime");

    if let Err(e) = runtime.block_on(run_agent()) {
        eprintln!("[CyberFence] Agent exited with error: {}", e);
        std::process::exit(1);
    }
}

// ── Core async agent logic ────────────────────────────────────────────────────
//
// This function is called from BOTH console mode (above) and service mode
// (via service.rs). It owns the full event pipeline.

pub async fn run_agent() -> Result<()> {
    // ── 1. Load configuration ──────────────────────────────────────────────
    let config = AgentConfig::load_default().unwrap_or_else(|e| {
        eprintln!("[CyberFence] Config load failed: {} — using defaults", e);
        AgentConfig::default()
    });

    // ── 2. Initialize structured logging ──────────────────────────────────
    // Must happen before any tracing calls.
    if let Err(e) = init_subscriber(&config) {
        eprintln!("[CyberFence] Logger init failed: {}", e);
        // Non-fatal: continue with stderr only
    }

    info!(
        version = env!("CARGO_PKG_VERSION"),
        mode    = if cfg!(target_os = "windows") { "windows" } else { "dev" },
        "CyberFence Endpoint Agent starting"
    );

    let watch_dirs = config.watch_dirs();
    info!(
        dirs  = ?watch_dirs,
        count = watch_dirs.len(),
        "Resolved watch directories"
    );

    // ── 3. Build the channel topology ─────────────────────────────────────
    //
    //  monitor_tx ──[FileEvent]──► EventFanout
    //                               ├─[FileEvent]─► logger_tx ──► EventLogger
    //                               └─[FileEvent]─► scanner_tx ► ScanEngine
    //  result_tx  ◄─[ScanResult]── ScanEngine
    //  summary_tx ◄─[ScanSummary]─ ScanEngine (full/quick scans)
    //
    let buf = config.monitor.ring_buffer_cap;

    let (monitor_tx,  monitor_rx)  = mpsc::channel::<cf_common::FileEvent>(buf);
    let (logger_tx,   logger_rx)   = mpsc::channel::<cf_common::FileEvent>(buf);
    let (scanner_tx,  scanner_rx)  = mpsc::channel::<cf_common::FileEvent>(buf);
    let (result_tx,   result_rx)   = mpsc::channel::<cf_common::ScanResult>(buf);
    let (_summary_tx, summary_rx)  = mpsc::channel::<cf_common::ScanSummary>(16);

    // ── 4. EventFanout task ───────────────────────────────────────────────
    // Bridges the single monitor channel to both the logger and scanner.
    // Non-blocking sends: if a downstream channel is full, the event is
    // dropped for that consumer rather than blocking the watcher thread.
    let fanout = tokio::spawn(async move {
        let mut rx: mpsc::Receiver<cf_common::FileEvent> = monitor_rx;
        while let Some(event) = rx.recv().await {
            let _ = logger_tx.try_send(event.clone());
            let _ = scanner_tx.try_send(event);
        }
        info!("EventFanout: monitor channel closed — shutting down");
    });

    // ── 5. FileMonitor task ───────────────────────────────────────────────
    let monitor        = FileMonitor::new(config.clone(), monitor_tx);
    let monitor_handle = tokio::spawn(async move {
        if let Err(e) = monitor.run().await {
            error!("FileMonitor exited with error: {}", e);
        }
    });

    // ── 6. EventLogger task ───────────────────────────────────────────────
    let logger        = EventLogger::new(logger_rx);
    let logger_handle = tokio::spawn(async move {
        if let Err(e) = logger.run().await {
            error!("EventLogger exited with error: {}", e);
        }
    });

    // ── 7. ScanEngine task (Phase 2 — degrades gracefully if ClamAV missing)
    let scan_engine    = ScanEngine::new(config.clone(), scanner_rx, result_tx);
    let scanner_handle = tokio::spawn(async move {
        if let Err(e) = scan_engine.run().await {
            error!("ScanEngine exited with error: {}", e);
        }
    });

    // ── 8. ScanResultWorker task ──────────────────────────────────────────
    let result_worker  = ScanResultWorker::new(result_rx, summary_rx);
    let result_handle  = tokio::spawn(async move {
        if let Err(e) = result_worker.run().await {
            error!("ScanResultWorker exited with error: {}", e);
        }
    });

    info!(
        scanning  = config.scanner.enabled,
        "CyberFence agent fully started"
    );
    info!("Watching: Downloads · Desktop · Documents (+ configured dirs)");
    info!("Press Ctrl-C to stop (console mode)");

    // ── 9. Wait for shutdown signal ───────────────────────────────────────
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Ctrl-C received — initiating graceful shutdown");
        }
        _ = monitor_handle => { error!("FileMonitor task exited unexpectedly"); }
        _ = logger_handle  => { error!("EventLogger task exited unexpectedly"); }
        _ = scanner_handle => { error!("ScanEngine task exited unexpectedly"); }
        _ = result_handle  => { error!("ScanResultWorker task exited unexpectedly"); }
        _ = fanout         => { error!("EventFanout task exited unexpectedly"); }
    }

    info!("CyberFence agent stopped");
    Ok(())
}

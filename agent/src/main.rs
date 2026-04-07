//! cf-agent — CyberFence Endpoint Protection Agent
//!
//! # Integration architecture
//!
//! This is the central integration point. Three major subsystems connect here:
//!
//! ```text
//!  ┌─────────────────────────────────────────────────────────────────────┐
//!  │                        cf-agent (this binary)                        │
//!  │                                                                       │
//!  │  OS kernel                                                            │
//!  │     ↓ ReadDirectoryChangesW                                           │
//!  │  FileMonitor (cf-monitor)                                             │
//!  │     ↓ FileEvent [MPSC]                                               │
//!  │  EventFanout                                                          │
//!  │     ├──► cf-logger::EventLogger    → agent-YYYY-MM-DD.jsonl          │
//!  │     └──► cf-scanner::ScanEngine   → CyberFence Engine subprocess     │
//!  │              ↓ ScanResult [MPSC]                                      │
//!  │          IntegrationWorker                                            │
//!  │              ├──► scan_logger     → scans-YYYY-MM-DD.jsonl           │
//!  │              ├──► AgentState      → in-memory threat/history list     │
//!  │              └──► IpcServer       → ThreatAlert push to UI            │
//!  │                                                                       │
//!  │  IpcServer  ◄──[named pipe]──► Tauri UI                              │
//!  │     ↑ Commands (GetStatus, GetThreats, RunScan…)                      │
//!  │     ↓ Responses + push events (ThreatAlert, ScanProgress)            │
//!  └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # How file events trigger scans
//!
//! 1. notify-rs detects a file change on the OS level
//! 2. cf-monitor emits a `FileEvent` to the MPSC channel
//! 3. EventFanout sends a clone to BOTH the logger AND the scanner
//! 4. ScanEngine's `event.is_scannable()` check gates which files get scanned
//! 5. clamscan subprocess runs; ScanResult emitted on result channel
//! 6. IntegrationWorker receives ScanResult and:
//!    - Writes to scan log JSONL
//!    - Updates AgentState (threat list, counters)
//!    - Broadcasts ThreatAlert to UI via IpcServer if threat found
//!
//! # How the UI gets data
//!
//! Two paths — both work independently:
//!   A) Named pipe: UI calls get_threats() → AgentState.get_recent_threats()
//!   B) Log files:  UI reads scans-YYYY-MM-DD.jsonl directly (log_reader.rs)
//!
//! Path A is instant (in-memory). Path B works even if the UI was closed
//! when the threat was detected.

#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]

use std::sync::Arc;
use anyhow::Result;
use cf_config::AgentConfig;
use cf_ipc::protocol::{AgentEvent, ThreatPayload};
use cf_logger::{init_subscriber, EventLogger};
use cf_monitor::FileMonitor;
use cf_scanner::{
    scan_logger::ScanLogger,
    ScanEngine,
};
use cf_common::scan::ScanVerdict;
use tokio::sync::mpsc;
use tracing::{error, info};

mod ipc_server;
mod service;
mod state;

use ipc_server::IpcTask;
use state::AgentState;

// ── Entry point ────────────────────────────────────────────────────────────────

fn main() {
    #[cfg(target_os = "windows")]
    {
        match service::try_start_as_service() {
            Ok(true)  => return,
            Ok(false) => {}
            Err(e)    => eprintln!("[CyberFence] Service dispatcher error: {} — console mode", e),
        }
    }

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

// ── Core async agent ──────────────────────────────────────────────────────────

pub async fn run_agent() -> Result<()> {
    // ── 1. Config ──────────────────────────────────────────────────────────
    let config = AgentConfig::load_default().unwrap_or_else(|e| {
        eprintln!("[CyberFence] Config load failed: {} — using defaults", e);
        AgentConfig::default()
    });

    // ── 2. Logging ─────────────────────────────────────────────────────────
    if let Err(e) = init_subscriber(&config) {
        eprintln!("[CyberFence] Logger init failed: {}", e);
    }

    info!(version = env!("CARGO_PKG_VERSION"), "CyberFence Endpoint Agent starting");

    let watch_dirs = config.watch_dirs();
    info!(dirs = ?watch_dirs, "Resolved watch directories");

    // ── 3. Shared state ────────────────────────────────────────────────────
    // AgentState is the single source of truth for the IPC server.
    // All tasks write to it; the UI reads from it via named pipe.
    let state = Arc::new(AgentState::default());

    // ── 4. Scan scheduler trigger channel ──────────────────────────────────
    // The IPC server sends ScanTrigger values here when the UI requests a scan.
    let (scan_trigger_tx, scan_trigger_rx) = mpsc::channel::<ipc_server::ScanTrigger>(4);

    // ── 5. IPC server ──────────────────────────────────────────────────────
    // The IPC server must start BEFORE the scan pipeline so we have the
    // event broadcaster reference to pass to IntegrationWorker.
    let ipc_task = IpcTask::new(Arc::clone(&state), scan_trigger_tx);

    // ── 6. Build event channels ────────────────────────────────────────────
    let buf = config.monitor.ring_buffer_cap;

    let (monitor_tx,  monitor_rx)  = mpsc::channel::<cf_common::FileEvent>(buf);
    let (logger_tx,   logger_rx)   = mpsc::channel::<cf_common::FileEvent>(buf);
    let (scanner_tx,  scanner_rx)  = mpsc::channel::<cf_common::FileEvent>(buf);
    let (result_tx,   mut result_rx) = mpsc::channel::<cf_common::ScanResult>(buf);
    let (_summary_tx, summary_rx)  = mpsc::channel::<cf_common::ScanSummary>(16);

    // ── 7. EventFanout ─────────────────────────────────────────────────────
    // Counts every file event for the AgentState dashboard counter.
    let state_fanout = Arc::clone(&state);
    let fanout = tokio::spawn(async move {
        let mut rx: mpsc::Receiver<cf_common::FileEvent> = monitor_rx;
        while let Some(event) = rx.recv().await {
            // Count every event for the files_monitored_today KPI
            state_fanout.record_file_event();
            let _ = logger_tx.try_send(event.clone());
            let _ = scanner_tx.try_send(event);
        }
        info!("EventFanout: monitor channel closed");
    });

    // ── 8. FileMonitor ─────────────────────────────────────────────────────
    let monitor        = FileMonitor::new(config.clone(), monitor_tx);
    let monitor_handle = tokio::spawn(async move {
        if let Err(e) = monitor.run().await { error!("FileMonitor: {}", e); }
    });

    // ── 9. EventLogger ─────────────────────────────────────────────────────
    let logger        = EventLogger::new(logger_rx);
    let logger_handle = tokio::spawn(async move {
        if let Err(e) = logger.run().await { error!("EventLogger: {}", e); }
    });

    // ── 10. ScanEngine ─────────────────────────────────────────────────────
    let scan_engine    = ScanEngine::new(config.clone(), scanner_rx, result_tx.clone());
    let scanner_handle = tokio::spawn(async move {
        if let Err(e) = scan_engine.run().await { error!("ScanEngine: {}", e); }
    });

    // ── 11. IntegrationWorker ──────────────────────────────────────────────
    // This is the key integration component: it reads ScanResults and:
    //   a) writes to the scan log JSONL file (for UI log_reader fallback)
    //   b) updates AgentState in memory (for fast IPC responses)
    //   c) broadcasts ThreatAlert to the UI via the IPC server
    let ipc_broadcaster = Arc::clone(&ipc_task.server);
    let scan_log = ScanLogger::with_default_dir();
    let state_worker = Arc::clone(&state);
    let result_worker = tokio::spawn(async move {
        while let Some(scan_result) = result_rx.recv().await {
            let is_threat  = scan_result.verdict.is_threat();
            let verdict    = scan_result.verdict.label();
            let action     = if matches!(scan_result.verdict, ScanVerdict::Infected(_)) { "QUARANTINED" } else { "LOGGED" };

            // a) Persist to scan log JSONL
            if let Err(e) = scan_log.write(&scan_result, action) {
                error!("Failed to write scan log: {}", e);
            }

            // b) Update in-memory state
            if is_threat {
                let threat = ThreatPayload {
                    id:           scan_result.id.to_string(),
                    detected_at:  scan_result.scanned_at.to_rfc3339(),
                    path:         scan_result.path.display().to_string(),
                    verdict:      verdict.to_string(),
                    threat_name:  match &scan_result.verdict {
                        ScanVerdict::Infected(n) | ScanVerdict::Suspicious(n) => n.clone(),
                        _ => "Unknown".to_string(),
                    },
                    severity:     scan_result.severity().to_string(),
                    action_taken: action.to_string(),
                    scan_type:    "ON_ACCESS".to_string(),
                    extension:    scan_result.path.extension()
                                     .and_then(|e| e.to_str()).unwrap_or("").to_lowercase(),
                    size_bytes:   scan_result.size_bytes,
                };

                state_worker.record_threat(threat.clone());

                // c) Push alert to UI via IPC
                ipc_broadcaster.broadcast(AgentEvent::ThreatAlert(threat));
            }
        }
        info!("IntegrationWorker: result channel closed");
    });

    // ── 12. Scan scheduler (listens for UI scan requests) ──────────────────
    let config_sched  = config.clone();
    let result_tx_sched = result_tx.clone();
    let state_sched   = Arc::clone(&state);
    let sched_handle  = tokio::spawn(async move {
        let mut rx = scan_trigger_rx;
        while let Some(trigger) = rx.recv().await {
            match trigger {
                ipc_server::ScanTrigger::QuickScan => {
                    info!("Starting UI-triggered quick scan");
                    // Phase 2: spawn FullScanner::run_quick_scan()
                    // For now, record a scan started event
                }
                ipc_server::ScanTrigger::FullScan => {
                    info!("Starting UI-triggered full scan");
                }
            }
        }
    });

    // ── 13. IPC server ─────────────────────────────────────────────────────
    let ipc_handle = tokio::spawn(async move {
        if let Err(e) = ipc_task.run().await { error!("IpcServer: {}", e); }
    });

    info!(
        scanning  = config.scanner.enabled,
        pipe      = %cf_ipc::pipe_path(),
        "CyberFence agent fully started"
    );
    info!("Monitoring: Downloads · Desktop · Documents");
    info!("IPC pipe:   {} (UI connects here)", cf_ipc::pipe_path());
    info!("Press Ctrl-C to stop");

    // ── 14. Wait for shutdown ──────────────────────────────────────────────
    tokio::select! {
        _ = tokio::signal::ctrl_c() => { info!("Ctrl-C — shutting down"); }
        _ = monitor_handle  => { error!("FileMonitor exited unexpectedly"); }
        _ = logger_handle   => { error!("EventLogger exited unexpectedly"); }
        _ = scanner_handle  => { error!("ScanEngine exited unexpectedly"); }
        _ = result_worker   => { error!("IntegrationWorker exited unexpectedly"); }
        _ = sched_handle    => { error!("Scheduler exited unexpectedly"); }
        _ = ipc_handle      => { error!("IpcServer exited unexpectedly"); }
        _ = fanout          => { error!("EventFanout exited unexpectedly"); }
    }

    info!("CyberFence agent stopped");
    Ok(())
}

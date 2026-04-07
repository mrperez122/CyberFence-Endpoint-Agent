//! cf-agent — CyberFence Endpoint Protection Agent
//!
//! Entry point for the background daemon process.
//!
//! # Startup sequence
//!
//! 1. Load config from disk (or defaults)
//! 2. Initialize tracing subscriber (file + stdout)
//! 3. Resolve watch directories
//! 4. Spawn FileMonitor task → produces FileEvents on MPSC channel
//! 5. Spawn EventLogger task  → consumes FileEvents, writes audit log
//! 6. Wait for Ctrl-C / SIGTERM → graceful shutdown
//!
//! # Phase 2 additions (scanner not yet implemented)
//!
//! ```text
//! FileMonitor → [event_tx] → EventFanout ─┬→ EventLogger
//!                                          └→ ScanEngine
//! ```

use anyhow::Result;
use cf_config::AgentConfig;
use cf_logger::{init_subscriber, EventLogger};
use cf_monitor::FileMonitor;
use tokio::sync::mpsc;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    // ── 1. Load configuration ─────────────────────────────────────────────────
    let config = AgentConfig::load_default().unwrap_or_else(|e| {
        // Can't log yet — print to stderr
        eprintln!("[CyberFence] Config load failed: {} — using defaults", e);
        AgentConfig::default()
    });

    // ── 2. Initialize logging ─────────────────────────────────────────────────
    if let Err(e) = init_subscriber(&config) {
        eprintln!("[CyberFence] Logger init failed: {}", e);
        // Non-fatal: continue without file logging
    }

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "CyberFence Endpoint Agent starting"
    );

    let watch_dirs = config.watch_dirs();
    info!(dirs = ?watch_dirs, "Resolved watch directories");

    // ── 3. Build the event channel ────────────────────────────────────────────
    //
    // Phase 1: single consumer (logger only).
    // Phase 2: EventFanout will broadcast to logger + scanner.
    let (event_tx, event_rx) = mpsc::channel(config.monitor.ring_buffer_cap);

    // ── 4. Spawn FileMonitor ──────────────────────────────────────────────────
    let monitor       = FileMonitor::new(config.clone(), event_tx);
    let monitor_handle = tokio::spawn(async move {
        if let Err(e) = monitor.run().await {
            error!("FileMonitor exited with error: {}", e);
        }
    });

    // ── 5. Spawn EventLogger ──────────────────────────────────────────────────
    let logger        = EventLogger::new(event_rx);
    let logger_handle = tokio::spawn(async move {
        if let Err(e) = logger.run().await {
            error!("EventLogger exited with error: {}", e);
        }
    });

    info!("CyberFence agent fully started — press Ctrl-C to stop");

    // ── 6. Wait for shutdown signal ───────────────────────────────────────────
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
    }

    info!("CyberFence agent stopped");
    Ok(())
}

//! cf-monitor — real-time file system monitoring component.
//!
//! # Architecture
//!
//! ```text
//! WatcherTask (notify-rs OS watcher)
//!     ↓  raw notify::Event
//! FilterTask (debounce + exclusion rules)
//!     ↓  FileEvent
//! EventSender (tokio MPSC → consumer)
//! ```
//!
//! # Usage
//!
//! ```rust,no_run
//! use cf_config::AgentConfig;
//! use cf_monitor::FileMonitor;
//! use tokio::sync::mpsc;
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = AgentConfig::default();
//!     let (tx, mut rx) = mpsc::channel(2000);
//!
//!     let monitor = FileMonitor::new(config, tx);
//!     let handle  = tokio::spawn(async move { monitor.run().await });
//!
//!     while let Some(event) = rx.recv().await {
//!         println!("[{}] {} → {:?}", event.kind, event.path.display(), event.scan_readiness);
//!     }
//! }
//! ```

pub mod debounce;
pub mod filter;
pub mod watcher;

use anyhow::Result;
use cf_common::events::FileEvent;
use cf_config::AgentConfig;
use tokio::sync::mpsc;
use tracing::{error, info};

/// Main file monitoring service.
///
/// Owns the notify-rs watcher and feeds a tokio MPSC channel with
/// `FileEvent` values that downstream consumers (scanner, logger) can read.
pub struct FileMonitor {
    config: AgentConfig,
    event_tx: mpsc::Sender<FileEvent>,
}

impl FileMonitor {
    /// Create a new monitor. The caller owns `event_tx`; downstream code
    /// should hold the corresponding `Receiver`.
    pub fn new(config: AgentConfig, event_tx: mpsc::Sender<FileEvent>) -> Self {
        Self { config, event_tx }
    }

    /// Start monitoring. This method drives the watcher loop and does not
    /// return until a shutdown signal is received or an unrecoverable error
    /// occurs. Run this inside `tokio::spawn`.
    pub async fn run(self) -> Result<()> {
        if !self.config.monitor.enabled {
            info!("File monitoring is disabled in config — skipping");
            return Ok(());
        }

        let watch_dirs = self.config.watch_dirs();
        if watch_dirs.is_empty() {
            error!("No watch directories exist on this system — cannot start monitor");
            anyhow::bail!("No valid watch directories found");
        }

        info!(
            dirs = ?watch_dirs,
            "Starting CyberFence file monitor"
        );

        watcher::run_watcher(self.config, self.event_tx, watch_dirs).await
    }
}

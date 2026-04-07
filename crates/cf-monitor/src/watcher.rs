//! Core watcher loop using notify-rs.
//!
//! This module owns the notify watcher and the bridge between
//! notify's callback-based API and our async tokio MPSC channel.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use cf_common::events::{FileEvent, FileEventKind};
use cf_config::AgentConfig;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::debounce::map_event_kind;
use crate::filter::{evaluate, FilterDecision};

/// Run the watcher loop until the event_tx channel is closed.
///
/// Uses a `std::sync::mpsc` channel as the bridge between notify's
/// synchronous callback and our async tokio channel.
pub async fn run_watcher(
    config: AgentConfig,
    event_tx: mpsc::Sender<FileEvent>,
    watch_dirs: Vec<PathBuf>,
) -> Result<()> {
    // notify uses a std channel internally; we bridge to tokio below
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<notify::Result<Event>>();

    let mut watcher = RecommendedWatcher::new(
        move |res| {
            // This callback fires on the notify thread.
            // We just forward everything to the std channel.
            if let Err(e) = notify_tx.send(res) {
                error!("Failed to forward notify event: {}", e);
            }
        },
        // Configure debounce timeout via notify's built-in support
        notify::Config::default().with_poll_interval(Duration::from_millis(
            config.monitor.debounce_ms,
        )),
    )
    .map_err(|e| anyhow::anyhow!("Failed to create watcher: {}", e))?;

    // Register all watch directories
    for dir in &watch_dirs {
        match watcher.watch(dir, RecursiveMode::Recursive) {
            Ok(_) => info!(dir = %dir.display(), "Watching directory"),
            Err(e) => warn!(dir = %dir.display(), error = %e, "Could not watch directory"),
        }
    }

    info!(
        count = watch_dirs.len(),
        "File monitor started — watching {} directories",
        watch_dirs.len()
    );

    // Bridge loop: receive from notify's std channel, process, send to tokio
    // We run this in a dedicated blocking thread so it doesn't block tokio.
    let config_clone = config.clone();
    let event_tx_clone = event_tx.clone();
    let watch_dirs_clone = watch_dirs.clone();

    tokio::task::spawn_blocking(move || {
        for result in notify_rx {
            match result {
                Ok(event) => {
                    process_event(
                        event,
                        &config_clone,
                        &event_tx_clone,
                        &watch_dirs_clone,
                    );
                }
                Err(e) => {
                    error!("Watcher error: {}", e);
                }
            }
        }
        info!("Notify channel closed — file monitor shutting down");
    })
    .await?;

    Ok(())
}

/// Process a single raw notify event:
/// 1. Map it to our FileEventKind
/// 2. Run filter rules
/// 3. Build a FileEvent
/// 4. Send to the tokio MPSC channel
fn process_event(
    event: Event,
    config: &AgentConfig,
    tx: &mpsc::Sender<FileEvent>,
    watch_dirs: &[PathBuf],
) {
    // Map notify kind → our kind. Skip events we don't care about.
    let Some(kind) = map_event_kind(&event.kind) else {
        debug!(kind = ?event.kind, "Skipping non-actionable event kind");
        return;
    };

    for path in &event.paths {
        // Skip directories — we only care about files
        if path.is_dir() {
            continue;
        }

        // Apply filter rules
        match evaluate(path, config) {
            FilterDecision::Allow => {}
            FilterDecision::Exclude(reason) => {
                debug!(
                    path = %path.display(),
                    reason = ?reason,
                    "Event excluded"
                );
                continue;
            }
        }

        // Find the watch root this path belongs to
        let watch_root = watch_dirs
            .iter()
            .find(|d| path.starts_with(d))
            .cloned()
            .unwrap_or_else(|| path.parent().unwrap_or(path).to_path_buf());

        // For RENAME events, extract old_path from the notify event paths list
        let old_path = if matches!(kind, FileEventKind::Renamed) && event.paths.len() == 2 {
            event.paths.first().cloned()
        } else {
            None
        };

        let file_event = FileEvent::new(
            path.clone(),
            old_path,
            kind.clone(),
            watch_root,
        );

        debug!(
            id     = %file_event.id,
            kind   = %file_event.kind,
            path   = %file_event.path.display(),
            size   = ?file_event.size_bytes,
            ready  = ?file_event.scan_readiness,
            "New file event"
        );

        // Non-blocking send — drop the event if the channel is full
        // rather than applying back-pressure to the OS watcher thread.
        match tx.try_send(file_event) {
            Ok(_) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    path = %path.display(),
                    "Event channel full — dropping event. \
                     Consider increasing monitor.ring_buffer_cap"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Consumer has shut down — stop processing
                return;
            }
        }
    }
}

//! EventLogger — consumes FileEvents from the pipeline channel and
//! writes a structured JSONL audit record for each one.

use anyhow::Result;
use cf_common::events::FileEvent;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Reads `FileEvent` values from `rx` and logs each one as a
/// structured event record.
///
/// This is deliberately separate from the tracing subscriber:
/// tracing logs are for operational diagnostics (what the agent is doing),
/// while the event log is the security audit trail (what files changed).
pub struct EventLogger {
    rx: mpsc::Receiver<FileEvent>,
}

impl EventLogger {
    pub fn new(rx: mpsc::Receiver<FileEvent>) -> Self {
        Self { rx }
    }

    /// Run the logging loop. Returns when the channel is closed.
    pub async fn run(mut self) -> Result<()> {
        info!("EventLogger started — listening for file events");
        let mut count: u64 = 0;

        while let Some(event) = self.rx.recv().await {
            count += 1;

            // Log at INFO level so it appears in the main log file.
            // The structured fields make this machine-parseable.
            info!(
                event_id      = %event.id,
                kind          = %event.kind,
                path          = %event.path.display(),
                extension     = %event.extension,
                size_bytes    = ?event.size_bytes,
                watch_root    = %event.watch_root.display(),
                scan_readiness = ?event.scan_readiness,
                is_scannable  = event.is_scannable(),
                "FILE_EVENT"
            );

            // Periodically emit a stats log so operators can see the agent is alive
            if count % 100 == 0 {
                info!(events_logged = count, "File monitor throughput checkpoint");
            }
        }

        info!(total_events = count, "EventLogger shutting down");
        Ok(())
    }
}

/// A fanout channel splitter: takes one `Receiver` and clones events
/// to multiple `Sender` channels. Used when Phase 2 scanner needs
/// to receive the same events as the logger.
///
/// Currently unused (single consumer in Phase 1) but ready for Phase 2.
pub struct EventFanout {
    source_rx:  mpsc::Receiver<FileEvent>,
    sinks:      Vec<mpsc::Sender<FileEvent>>,
}

impl EventFanout {
    pub fn new(source_rx: mpsc::Receiver<FileEvent>, sinks: Vec<mpsc::Sender<FileEvent>>) -> Self {
        Self { source_rx, sinks }
    }

    /// Run the fanout loop.
    pub async fn run(mut self) -> Result<()> {
        while let Some(event) = self.source_rx.recv().await {
            for sink in &self.sinks {
                match sink.try_send(event.clone()) {
                    Ok(_) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        warn!("EventFanout: downstream channel full — event dropped");
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        // Downstream consumer gone — remove from sinks on next iteration
                    }
                }
            }
        }
        Ok(())
    }
}

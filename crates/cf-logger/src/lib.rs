//! cf-logger — structured event logging for the CyberFence agent.
//!
//! # What this provides
//!
//! 1. **Tracing subscriber** — configures the global `tracing` subscriber
//!    to write structured JSON logs to a rotating daily file.
//!
//! 2. **EventLogger** — an async task that reads `FileEvent` values from
//!    the pipeline channel and writes a one-line JSON record per event.
//!    This is the "audit trail" used by the UI's Event Log view.
//!
//! # Log format (one JSON object per line)
//!
//! ```json
//! {
//!   "timestamp": "2026-04-07T01:00:00.000Z",
//!   "level": "INFO",
//!   "module": "cf_monitor::watcher",
//!   "message": "New file event",
//!   "id": "550e8400-e29b-41d4-a716-446655440000",
//!   "kind": "CREATED",
//!   "path": "/home/user/Downloads/setup.exe",
//!   "size_bytes": 2048576,
//!   "scan_readiness": "PENDING_SCAN"
//! }
//! ```

pub mod subscriber;
pub mod event_logger;

pub use event_logger::EventLogger;
pub use subscriber::init_subscriber;

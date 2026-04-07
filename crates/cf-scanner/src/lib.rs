//! cf-scanner — ClamAV-backed malware scanning for the CyberFence agent.
//!
//! # Architecture
//!
//! ```text
//! FileEvent (from cf-monitor via MPSC)
//!     ↓
//! ScanQueue (bounded tokio channel)
//!     ↓
//! ScanWorker × N  (tokio::spawn_blocking → clamscan subprocess)
//!     ↓
//! ScanResult (emitted to result channel)
//!     ↓
//! cf-logger (persists) + cf-broker (acts — Phase 3)
//! ```
//!
//! # ClamAV integration strategy
//!
//! We call ClamAV as a **subprocess** (`clamscan --no-summary --infected`).
//! This avoids complex FFI/bindgen and works with any standard ClamAV install
//! on both Windows and macOS without a C toolchain.
//!
//! FFI (libclamav) integration is planned for Phase 3 when we need
//! sub-millisecond scan latency for on-access scanning at high volume.

pub mod clamav;
pub mod engine;
pub mod full_scan;
pub mod worker;

pub use engine::ScanEngine;
pub use full_scan::FullScanner;

//! cf-common — shared types for the CyberFence Endpoint Agent
//!
//! This crate is the single source of truth for all event types,
//! severity levels, and error definitions that cross crate boundaries.

pub mod errors;
pub mod events;

pub use errors::CfError;
pub use events::{FileEvent, FileEventKind, ScanReadiness, Severity};

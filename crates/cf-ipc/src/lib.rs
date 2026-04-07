//! cf-ipc — Inter-process communication between cf-agent and the Tauri UI.
//!
//! # Transport
//!
//! | Platform | Transport | Path |
//! |----------|-----------|------|
//! | Windows  | Named pipe | `\\.\pipe\CyberFenceAgent` |
//! | macOS    | Unix socket | `~/Library/Application Support/CyberFence/agent.sock` |
//! | Linux    | Unix socket | `/tmp/cyberfence/agent.sock` |
//!
//! # Wire format
//!
//! Every message is length-prefixed:
//! ```text
//! [4 bytes LE u32: payload length][JSON payload bytes]
//! ```
//! Maximum message size: 4 MB.
//!
//! # Message flow
//!
//! ```text
//! Svelte invoke('get_status')
//!     ↓ Tauri IPC
//! commands.rs → IpcClient::send_command(Command::GetStatus)
//!     ↓ named pipe / socket
//! IpcServer::handle_connection()
//!     ↓ match command
//! Response::Status(AgentStatus) → serialized JSON
//!     ↓ named pipe / socket
//! IpcClient → deserialize → Svelte store update
//!
//! SEPARATELY — agent pushes events proactively:
//! ScanResultWorker → EventBroadcaster::broadcast(Event::ThreatAlert)
//!     ↓ named pipe / socket to all connected UI clients
//! Svelte listen('threat_alert') → threats store update
//! ```

pub mod protocol;
pub mod server;
pub mod client;

pub use protocol::{Command, Response, AgentEvent, AgentStatusPayload, ThreatPayload, ScanHistoryPayload, ScanProgressPayload};
pub use server::IpcServer;
pub use client::IpcClient;

/// Platform-specific pipe/socket path
pub fn pipe_path() -> String {
    #[cfg(target_os = "windows")]
    { r"\\.\pipe\CyberFenceAgent".to_string() }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/Library/Application Support/CyberFence/agent.sock", home)
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    { "/tmp/cyberfence/agent.sock".to_string() }
}

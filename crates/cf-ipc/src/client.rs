//! IPC client — used by the Tauri UI backend to communicate with cf-agent.
//!
//! # Usage
//!
//! ```rust,ignore
//! let mut client = IpcClient::connect().await?;
//! let status = client.get_status().await?;
//! ```

use anyhow::{Context, Result};
use tracing::{debug, warn};

use crate::protocol::{Command, Response, AgentEvent};

// ── IpcClient ─────────────────────────────────────────────────────────────────

/// Manages a single connection to the cf-agent IPC endpoint.
pub struct IpcClient {
    #[cfg(target_os = "windows")]
    stream: tokio::net::windows::named_pipe::NamedPipeClient,
    #[cfg(not(target_os = "windows"))]
    stream: tokio::net::UnixStream,
}

impl IpcClient {
    /// Connect to the running cf-agent.
    /// Returns an error if the agent is not running.
    pub async fn connect() -> Result<Self> {
        let path = crate::pipe_path();

        #[cfg(target_os = "windows")]
        {
            let stream = tokio::net::windows::named_pipe::ClientOptions::new()
                .open(&path)
                .with_context(|| format!("Cannot connect to IPC pipe: {}", path))?;
            Ok(Self { stream })
        }

        #[cfg(not(target_os = "windows"))]
        {
            let stream = tokio::net::UnixStream::connect(&path)
                .await
                .with_context(|| format!("Cannot connect to IPC socket: {}", path))?;
            Ok(Self { stream })
        }
    }

    /// Returns true if the agent IPC endpoint is reachable.
    pub async fn is_agent_running() -> bool {
        Self::connect().await.is_ok()
    }

    /// Send a command and wait for a response.
    pub async fn send(&mut self, command: &Command) -> Result<Response> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let frame = crate::protocol::encode(command)?;
        self.stream.write_all(&frame).await
            .context("Failed to send IPC command")?;

        // Read response length
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await
            .context("Failed to read IPC response length")?;

        let len = u32::from_le_bytes(len_buf) as usize;
        if len > 4 * 1024 * 1024 {
            anyhow::bail!("IPC response too large: {} bytes", len);
        }

        let mut payload = vec![0u8; len];
        self.stream.read_exact(&mut payload).await
            .context("Failed to read IPC response payload")?;

        crate::protocol::decode::<Response>(&payload)
            .context("Failed to decode IPC response")
    }

    // ── Convenience methods ────────────────────────────────────────────────

    pub async fn get_status(&mut self) -> Result<Response> {
        self.send(&Command::GetStatus).await
    }

    pub async fn get_threats(&mut self, limit: u32) -> Result<Response> {
        self.send(&Command::GetThreats { limit, since_hours: None }).await
    }

    pub async fn get_scan_history(&mut self, limit: u32) -> Result<Response> {
        self.send(&Command::GetScanHistory { limit }).await
    }

    pub async fn run_quick_scan(&mut self) -> Result<Response> {
        self.send(&Command::RunQuickScan).await
    }

    pub async fn run_full_scan(&mut self) -> Result<Response> {
        self.send(&Command::RunFullScan).await
    }
}

//! IPC server — runs inside cf-agent, accepts connections from the Tauri UI.
//!
//! # Connection handling
//!
//! Each connecting client gets its own task. Messages are read with a 4-byte
//! length prefix, dispatched to a handler, and responses are written back.
//!
//! Push events (ThreatAlert, ScanProgress) are broadcast to all connected
//! clients via a tokio broadcast channel.

use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{info, warn};
use anyhow::Result;

use crate::protocol::{AgentEvent, Command, Response};

// ── Event broadcaster ─────────────────────────────────────────────────────────

/// Broadcast channel for push events from the agent to all connected UI clients.
pub type EventSender = broadcast::Sender<AgentEvent>;
pub type EventReceiver = broadcast::Receiver<AgentEvent>;

pub fn event_channel() -> (EventSender, EventReceiver) {
    broadcast::channel(256)
}

// ── Handler trait ─────────────────────────────────────────────────────────────

/// Implement this trait in the agent to handle incoming UI commands.
/// The IpcServer calls these methods when a command arrives.
#[async_trait::async_trait]
pub trait CommandHandler: Send + Sync + 'static {
    async fn handle(&self, command: Command) -> Response;
}

// ── IpcServer ─────────────────────────────────────────────────────────────────

/// Named pipe / Unix socket server that bridges the UI to the agent.
pub struct IpcServer {
    pub event_tx: EventSender,
}

impl IpcServer {
    pub fn new() -> (Self, EventReceiver) {
        let (tx, rx) = event_channel();
        (Self { event_tx: tx }, rx)
    }

    /// Broadcast an event to all connected UI clients.
    pub fn broadcast(&self, event: AgentEvent) {
        // Ignore the error if no clients are connected
        let _ = self.event_tx.send(event);
    }

    /// Run the server. Accepts connections and spawns a task per client.
    /// The `handler` is called for each incoming Command.
    pub async fn run<H: CommandHandler>(self: Arc<Self>, handler: Arc<H>) -> Result<()> {
        let path = crate::pipe_path();
        info!(path = %path, "IPC server starting");

        #[cfg(target_os = "windows")]
        self.run_named_pipe(handler, &path).await?;

        #[cfg(not(target_os = "windows"))]
        self.run_unix_socket(handler, &path).await?;

        Ok(())
    }

    // ── Named pipe (Windows) ──────────────────────────────────────────────────
    #[cfg(target_os = "windows")]
    async fn run_named_pipe<H: CommandHandler>(
        self: Arc<Self>,
        handler: Arc<H>,
        path: &str,
    ) -> Result<()> {
        use tokio::net::windows::named_pipe::ServerOptions;

        loop {
            // Create a new pipe instance for each client
            let server = ServerOptions::new()
                .first_pipe_instance(false)
                .create(path)?;

            // Wait for a client to connect
            server.connect().await?;
            info!("IPC: UI client connected");

            let h     = Arc::clone(&handler);
            let s     = Arc::clone(&self);
            let event_rx = s.event_tx.subscribe();

            tokio::spawn(async move {
                handle_connection_windows(server, h, event_rx).await;
            });
        }
    }

    // ── Unix socket (macOS / Linux / dev) ─────────────────────────────────────
    #[cfg(not(target_os = "windows"))]
    async fn run_unix_socket<H: CommandHandler>(
        self: Arc<Self>,
        handler: Arc<H>,
        path: &str,
    ) -> Result<()> {
        use tokio::net::UnixListener;

        // Remove stale socket file if agent crashed without cleanup
        let _ = std::fs::remove_file(path);

        // Ensure parent dir exists
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(path)?;
        info!(path = %path, "IPC server listening (Unix socket)");

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    info!("IPC: UI client connected");
                    let h        = Arc::clone(&handler);
                    let event_rx = self.event_tx.subscribe();
                    tokio::spawn(async move {
                        handle_connection_unix(stream, h, event_rx).await;
                    });
                }
                Err(e) => {
                    error!("IPC accept error: {}", e);
                }
            }
        }
    }
}

// ── Per-connection handlers ───────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
async fn handle_connection_unix<H: CommandHandler>(
    mut stream: tokio::net::UnixStream,
    handler: Arc<H>,
    mut event_rx: EventReceiver,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut len_buf = [0u8; 4];
    let mut payload_buf = Vec::new();

    loop {
        tokio::select! {
            // Incoming command from UI
            result = stream.read_exact(&mut len_buf) => {
                if result.is_err() { break; }
                let len = u32::from_le_bytes(len_buf) as usize;
                if len > 4 * 1024 * 1024 { warn!("IPC: oversized message ({} bytes)", len); break; }
                payload_buf.resize(len, 0);
                if stream.read_exact(&mut payload_buf).await.is_err() { break; }

                match crate::protocol::decode::<Command>(&payload_buf) {
                    Ok(cmd) => {
                        let resp  = handler.handle(cmd).await;
                        match crate::protocol::encode(&resp) {
                            Ok(frame) => { let _ = stream.write_all(&frame).await; }
                            Err(e) => { warn!("IPC encode error: {}", e); }
                        }
                    }
                    Err(e) => { warn!("IPC decode error: {}", e); }
                }
            }

            // Push event from agent to UI
            evt = event_rx.recv() => {
                match evt {
                    Ok(event) => {
                        if let Ok(frame) = crate::protocol::encode(&event) {
                            if stream.write_all(&frame).await.is_err() { break; }
                        }
                    }
                    Err(_) => {} // lagged or closed
                }
            }
        }
    }

    info!("IPC: UI client disconnected");
}

// Windows version uses the named pipe stream type instead
#[cfg(target_os = "windows")]
async fn handle_connection_windows<H: CommandHandler>(
    mut stream: tokio::net::windows::named_pipe::NamedPipeServer,
    handler: Arc<H>,
    mut event_rx: EventReceiver,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut len_buf = [0u8; 4];
    let mut payload_buf = Vec::new();

    loop {
        tokio::select! {
            result = stream.read_exact(&mut len_buf) => {
                if result.is_err() { break; }
                let len = u32::from_le_bytes(len_buf) as usize;
                if len > 4 * 1024 * 1024 { break; }
                payload_buf.resize(len, 0);
                if stream.read_exact(&mut payload_buf).await.is_err() { break; }

                match crate::protocol::decode::<Command>(&payload_buf) {
                    Ok(cmd) => {
                        let resp = handler.handle(cmd).await;
                        if let Ok(frame) = crate::protocol::encode(&resp) {
                            let _ = stream.write_all(&frame).await;
                        }
                    }
                    Err(e) => { warn!("IPC decode: {}", e); }
                }
            }
            evt = event_rx.recv() => {
                if let Ok(event) = evt {
                    if let Ok(frame) = crate::protocol::encode(&event) {
                        if stream.write_all(&frame).await.is_err() { break; }
                    }
                }
            }
        }
    }
    info!("IPC: Windows client disconnected");
}

//! IPC server wiring for cf-agent.
//!
//! Implements `CommandHandler` from cf-ipc so the IpcServer can dispatch
//! incoming UI commands to the agent's internal services.
//!
//! # Component connections
//!
//! ```text
//! Tauri UI  ──[named pipe]──►  IpcServer (this module)
//!                                  ├─► get_status()     → reads scan log stats + agent state
//!                                  ├─► get_threats()    → reads scan log JSONL files
//!                                  ├─► get_scan_history → reads scan log JSONL files
//!                                  ├─► run_quick_scan   → sends to scan scheduler channel
//!                                  └─► run_full_scan    → sends to scan scheduler channel
//!
//! ScanResultWorker  ──────────►  EventBroadcaster
//!                                  └─► broadcast(ThreatAlert) → all connected UI clients
//! ```

use std::sync::Arc;
use anyhow::Result;
use cf_ipc::{
    server::CommandHandler, IpcServer,
    protocol::{
        Command, Response,
    },
};
use tokio::sync::mpsc;
use tracing::info;

use crate::state::AgentState;

// ── AgentCommandHandler ───────────────────────────────────────────────────────

/// Handles incoming IPC commands from the UI.
/// Has access to shared agent state and the scan scheduler channel.
pub struct AgentCommandHandler {
    state:         Arc<AgentState>,
    scan_trigger:  mpsc::Sender<ScanTrigger>,
}

/// Triggers that can be sent to the scan scheduler.
#[derive(Debug)]
pub enum ScanTrigger {
    QuickScan,
    FullScan,
}

impl AgentCommandHandler {
    pub fn new(state: Arc<AgentState>, scan_trigger: mpsc::Sender<ScanTrigger>) -> Self {
        Self { state, scan_trigger }
    }
}

#[async_trait::async_trait]
impl CommandHandler for AgentCommandHandler {
    async fn handle(&self, command: Command) -> Response {
        match command {
            Command::GetStatus => {
                Response::Status(self.state.to_status_payload())
            }

            Command::GetThreats { limit, since_hours: _ } => {
                let threats = self.state.get_recent_threats(limit as usize);
                Response::Threats(threats)
            }

            Command::GetScanHistory { limit } => {
                let history = self.state.get_scan_history(limit as usize);
                Response::ScanHistory(history)
            }

            Command::RunQuickScan => {
                let _ = self.scan_trigger.try_send(ScanTrigger::QuickScan);
                info!("UI requested quick scan");
                Response::ScanStarted {
                    job_id:    uuid::Uuid::new_v4().to_string(),
                    scan_type: "QUICK_SCAN".into(),
                }
            }

            Command::RunFullScan => {
                let _ = self.scan_trigger.try_send(ScanTrigger::FullScan);
                info!("UI requested full scan");
                Response::ScanStarted {
                    job_id:    uuid::Uuid::new_v4().to_string(),
                    scan_type: "FULL_SCAN".into(),
                }
            }

            Command::CancelScan { job_id } => {
                info!(id = %job_id, "UI cancelled scan");
                Response::ScanCancelled { job_id }
            }

            Command::DismissThreat { threat_id } => {
                self.state.dismiss_threat(&threat_id);
                Response::ThreatDismissed { threat_id }
            }

            Command::GetDefinitionsInfo => {
                Response::DefinitionsInfo(self.state.get_definitions_info())
            }
        }
    }
}

// ── IpcTask ───────────────────────────────────────────────────────────────────

/// Manages the IPC server and event broadcast.
pub struct IpcTask {
    pub server:  Arc<IpcServer>,
    handler:     Arc<AgentCommandHandler>,
}

impl IpcTask {
    pub fn new(state: Arc<AgentState>, scan_trigger: mpsc::Sender<ScanTrigger>) -> Self {
        let (server, _rx) = IpcServer::new();
        let server        = Arc::new(server);
        let handler       = Arc::new(AgentCommandHandler::new(state, scan_trigger));
        Self { server, handler }
    }

    /// Start the IPC server. Runs until the process exits.
    pub async fn run(self) -> Result<()> {
        let server  = Arc::clone(&self.server);
        let handler = Arc::clone(&self.handler);
        server.run(handler).await
    }
}

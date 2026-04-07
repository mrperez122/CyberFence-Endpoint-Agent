//! Tauri IPC command handlers.
//!
//! Each function is annotated with #[tauri::command] and registered in lib.rs.
//! The Svelte frontend calls these via:
//!   import { invoke } from '@tauri-apps/api/core';
//!   const status = await invoke('get_status');
//!
//! Phase 2: replace mock::* calls with named pipe IPC to cf-agent.

use tauri::AppHandle;
use crate::mock;

// ── Status ────────────────────────────────────────────────────────────────────

/// Returns current agent status: protection level, scan stats, definitions.
/// Phase 2: read from cf-agent named pipe → protection_status event.
#[tauri::command]
pub async fn get_status(_app: AppHandle) -> Result<mock::AgentStatus, String> {
    Ok(mock::mock_status())
}

/// Returns ClamAV definitions version and age.
/// Phase 2: read from cf-agent named pipe → definition_update event.
#[tauri::command]
pub async fn get_definitions_info(_app: AppHandle) -> Result<mock::DefinitionsInfo, String> {
    Ok(mock::mock_definitions())
}

// ── Scan history ──────────────────────────────────────────────────────────────

/// Returns the last N scan jobs with file counts and threat totals.
/// Phase 2: SELECT FROM scan_jobs in SQLite via cf-agent IPC.
#[tauri::command]
pub async fn get_scan_history(
    _app: AppHandle,
    #[allow(unused_variables)] limit: Option<u32>,
) -> Result<Vec<mock::ScanHistoryEntry>, String> {
    Ok(mock::mock_scan_history())
}

// ── Threats ───────────────────────────────────────────────────────────────────

/// Returns detected threats (infected + suspicious) with full metadata.
/// Phase 2: SELECT FROM threat_events WHERE severity >= MEDIUM via cf-agent IPC.
#[tauri::command]
pub async fn get_threats(
    _app: AppHandle,
    #[allow(unused_variables)] since_hours: Option<u32>,
) -> Result<Vec<mock::ThreatEntry>, String> {
    Ok(mock::mock_threats())
}

// ── Scan actions ──────────────────────────────────────────────────────────────

/// Trigger an immediate quick scan of high-risk directories.
/// Phase 2: send run_quick_scan command via cf-agent named pipe.
#[tauri::command]
pub async fn run_quick_scan(_app: AppHandle) -> Result<String, String> {
    // Phase 2: send to agent
    // agent_ipc::send(Command::RunQuickScan).await?;
    Ok("Quick scan started".to_string())
}

/// Trigger a full system scan.
/// Phase 2: send run_full_scan command via cf-agent named pipe.
#[tauri::command]
pub async fn run_full_scan(_app: AppHandle) -> Result<String, String> {
    // Phase 2: send to agent
    // agent_ipc::send(Command::RunFullScan).await?;
    Ok("Full scan started".to_string())
}

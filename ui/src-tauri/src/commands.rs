//! Tauri IPC command handlers.
//!
//! # Data flow (Phase 1–2)
//!
//! ```
//! Svelte: invoke('get_threats')
//!     ↓
//! commands::get_threats()
//!     ↓ read scan log files (log_reader.rs)
//!     ↓ OR fall back to mock data
//!     ↓
//! Vec<ThreatEntry> serialized to JSON → Svelte store
//! ```
//!
//! # Phase 3 upgrade path
//!
//! Replace `log_reader::read_recent_scans()` calls with:
//! ```rust
//! agent_ipc::send(Command::GetThreatFeed { limit }).await
//! ```

use tauri::AppHandle;
use crate::mock::{self, AgentStatus, DefinitionsInfo, ScanHistoryEntry, ThreatEntry};
use crate::log_reader;

// ── Status ────────────────────────────────────────────────────────────────────

/// Get overall agent protection status.
///
/// Phase 2: reads from scan log stats + agent heartbeat file.
/// Phase 3: named pipe `protection_status` event from cf-agent.
#[tauri::command]
pub async fn get_status(_app: AppHandle) -> Result<AgentStatus, String> {
    // Check if real log files exist — if yes, derive status from them
    let scans = log_reader::read_recent_scans(1);
    if !scans.is_empty() {
        let threats_total = scans.iter()
            .filter(|r| r.verdict == "INFECTED" || r.verdict == "SUSPICIOUS")
            .count() as u32;
        let files_scanned = scans.len() as u64;

        return Ok(AgentStatus {
            protection_status:     "PROTECTED".into(),
            realtime_monitoring:   true,
            scanning_enabled:      true,
            last_scan_time:        scans.first().map(|r| r.scanned_at.clone()),
            definitions_version:   "live".into(),
            definitions_age_hours: 0,
            files_monitored_today: files_scanned,
            threats_today:         threats_total,
            threats_total,
            agent_version:         env!("CARGO_PKG_VERSION").into(),
        });
    }

    // No real data yet — return mock data
    Ok(mock::mock_status())
}

/// Get CyberFence Engine definitions info.
#[tauri::command]
pub async fn get_definitions_info(_app: AppHandle) -> Result<DefinitionsInfo, String> {
    Ok(mock::mock_definitions())
}

// ── Scan history ──────────────────────────────────────────────────────────────

/// Get the last N scan job summaries.
///
/// Phase 2: reads from scan log files.
/// Phase 3: named pipe `get_scan_history` command.
#[tauri::command]
pub async fn get_scan_history(
    _app:  AppHandle,
    limit: Option<u32>,
) -> Result<Vec<ScanHistoryEntry>, String> {
    let limit = limit.unwrap_or(20) as usize;
    // For now, return mock data.
    // Phase 3: parse scan summary lines from log files.
    let mut history = mock::mock_scan_history();
    history.truncate(limit);
    Ok(history)
}

// ── Threats ───────────────────────────────────────────────────────────────────

/// Get recent threat detections.
///
/// Phase 2: reads from scan log JSONL, filters for verdict = INFECTED/SUSPICIOUS.
/// Phase 3: named pipe `get_threats` command.
#[tauri::command]
pub async fn get_threats(
    _app:        AppHandle,
    since_hours: Option<u32>,
) -> Result<Vec<ThreatEntry>, String> {
    let days = ((since_hours.unwrap_or(168)) / 24).max(1);
    let scans = log_reader::read_recent_scans(days);

    // If real scan log data exists, use it
    if !scans.is_empty() {
        let threats: Vec<ThreatEntry> = scans
            .into_iter()
            .filter(|r| r.verdict == "INFECTED" || r.verdict == "SUSPICIOUS")
            .map(|r| ThreatEntry {
                id:           r.id,
                detected_at:  r.scanned_at,
                path:         r.path,
                verdict:      r.verdict,
                threat_name:  r.threat_name.unwrap_or_else(|| "Unknown".into()),
                severity:     r.severity,
                action_taken: r.action,
                scan_type:    "ON_ACCESS".into(),
                extension:    r.extension,
                size_bytes:   r.size_bytes,
            })
            .collect();

        if !threats.is_empty() {
            return Ok(threats);
        }
    }

    // Fall back to mock data for development
    Ok(mock::mock_threats())
}

// ── Scan actions ──────────────────────────────────────────────────────────────

/// Trigger a quick scan.
///
/// Phase 3: sends `run_quick_scan` command via named pipe to cf-agent.
#[tauri::command]
pub async fn run_quick_scan(_app: AppHandle) -> Result<String, String> {
    // Phase 3: agent_ipc::send(Command::RunQuickScan).await
    tracing::info!("UI requested quick scan");
    Ok("Quick scan started".into())
}

/// Trigger a full scan.
///
/// Phase 3: sends `run_full_scan` command via named pipe to cf-agent.
#[tauri::command]
pub async fn run_full_scan(_app: AppHandle) -> Result<String, String> {
    tracing::info!("UI requested full scan");
    Ok("Full scan started".into())
}

/// Dismiss a threat from the threat list (mark as reviewed).
///
/// Phase 3: updates the SQLite event record via cf-agent IPC.
#[tauri::command]
pub async fn dismiss_threat(_app: AppHandle, threat_id: String) -> Result<(), String> {
    tracing::info!(id = %threat_id, "Threat dismissed by user");
    Ok(())
}

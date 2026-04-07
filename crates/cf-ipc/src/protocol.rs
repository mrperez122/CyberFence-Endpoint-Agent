//! Wire protocol types for the cf-agent ↔ UI IPC channel.
//!
//! All types derive Serialize + Deserialize and are transmitted as
//! length-prefixed JSON. The UI (Tauri) and agent both import this crate
//! so the types are always in sync.

use serde::{Deserialize, Serialize};
// ScanType and ScanVerdict available from cf_common if needed

// ── Commands (UI → Agent) ─────────────────────────────────────────────────────

/// Commands the UI can send to the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    /// Get current agent status (protection state, definitions age, etc.)
    GetStatus,
    /// Get recent threat detections from the scan log.
    GetThreats { limit: u32, since_hours: Option<u32> },
    /// Get scan job history.
    GetScanHistory { limit: u32 },
    /// Trigger an immediate quick scan.
    RunQuickScan,
    /// Trigger a full system scan.
    RunFullScan,
    /// Cancel the currently running scan job.
    CancelScan { job_id: String },
    /// Mark a threat as reviewed (dismissed in UI).
    DismissThreat { threat_id: String },
    /// Get current definitions info.
    GetDefinitionsInfo,
}

// ── Responses (Agent → UI, in response to a Command) ─────────────────────────

/// Agent's response to a Command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Status(AgentStatusPayload),
    Threats(Vec<ThreatPayload>),
    ScanHistory(Vec<ScanHistoryPayload>),
    ScanStarted { job_id: String, scan_type: String },
    ScanCancelled { job_id: String },
    ThreatDismissed { threat_id: String },
    DefinitionsInfo(DefinitionsInfoPayload),
    Error { message: String },
}

// ── Push events (Agent → UI, unprompted) ─────────────────────────────────────

/// Events the agent broadcasts to all connected UI clients without being asked.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AgentEvent {
    /// Real-time threat alert — fires immediately on INFECTED/SUSPICIOUS.
    ThreatAlert(ThreatPayload),
    /// Scan progress update — emitted every 100 files during a full/quick scan.
    ScanProgress(ScanProgressPayload),
    /// Scan job completed.
    ScanComplete { job_id: String, files_scanned: u64, threats_found: u32, duration_secs: i64 },
    /// Protection status changed (e.g. engine disabled, definitions outdated).
    StatusChanged(AgentStatusPayload),
    /// Definitions updated via freshclam.
    DefinitionsUpdated { version: String, virus_count: u64 },
}

// ── Payload types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentStatusPayload {
    pub protection_status:     String, // "PROTECTED" | "AT_RISK" | "SCANNING" | "DISABLED"
    pub realtime_monitoring:   bool,
    pub scanning_enabled:      bool,
    pub last_scan_time:        Option<String>,
    pub definitions_version:   String,
    pub definitions_age_hours: u32,
    pub files_monitored_today: u64,
    pub threats_today:         u32,
    pub threats_total:         u32,
    pub agent_version:         String,
    pub engine_version:        Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatPayload {
    pub id:           String,
    pub detected_at:  String,
    pub path:         String,
    pub verdict:      String,       // "INFECTED" | "SUSPICIOUS"
    pub threat_name:  String,
    pub severity:     String,       // "CRITICAL" | "MEDIUM"
    pub action_taken: String,       // "QUARANTINED" | "LOGGED"
    pub scan_type:    String,
    pub extension:    String,
    pub size_bytes:   Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanHistoryPayload {
    pub id:            String,
    pub scan_type:     String,
    pub started_at:    String,
    pub completed_at:  String,
    pub files_scanned: u64,
    pub threats_found: u32,
    pub duration_secs: i64,
    pub status:        String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgressPayload {
    pub job_id:        String,
    pub total_files:   u64,
    pub scanned_files: u64,
    pub threats_found: u32,
    pub current_file:  Option<String>,
    pub percent:       u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DefinitionsInfoPayload {
    pub version:     String,
    pub updated_at:  String,
    pub age_hours:   u32,
    pub virus_count: u64,
    pub status:      String,
}

// ── Framing helpers ───────────────────────────────────────────────────────────

/// Serialize a value to a length-prefixed JSON frame.
pub fn encode<T: Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    let json = serde_json::to_vec(value)?;
    let len  = json.len() as u32;
    let mut frame = Vec::with_capacity(4 + json.len());
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&json);
    Ok(frame)
}

/// Decode a value from a length-prefixed JSON frame payload (excluding the 4-byte header).
pub fn decode<T: for<'de> Deserialize<'de>>(payload: &[u8]) -> anyhow::Result<T> {
    Ok(serde_json::from_slice(payload)?)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_roundtrip() {
        let cmd = Command::GetThreats { limit: 20, since_hours: Some(24) };
        let frame = encode(&cmd).unwrap();
        // First 4 bytes are the length
        let len = u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(len, frame.len() - 4);
        let decoded: Command = decode(&frame[4..]).unwrap();
        assert!(matches!(decoded, Command::GetThreats { limit: 20, .. }));
    }

    #[test]
    fn response_roundtrip() {
        let resp = Response::Error { message: "test error".to_string() };
        let frame = encode(&resp).unwrap();
        let len = u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize;
        let decoded: Response = decode(&frame[4..]).unwrap();
        assert!(matches!(decoded, Response::Error { .. }));
        assert_eq!(len, frame.len() - 4);
    }

    #[test]
    fn event_roundtrip() {
        let evt = AgentEvent::DefinitionsUpdated {
            version: "26481".to_string(),
            virus_count: 8_000_000,
        };
        let frame = encode(&evt).unwrap();
        let decoded: AgentEvent = decode(&frame[4..]).unwrap();
        assert!(matches!(decoded, AgentEvent::DefinitionsUpdated { .. }));
    }
}

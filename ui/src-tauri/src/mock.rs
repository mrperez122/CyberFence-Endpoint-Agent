//! Mock data for development and testing.
//!
//! In production (Phase 3), commands.rs calls log_reader or named pipe IPC.
//! In development, commands.rs calls these mock functions when:
//!   - No scan log files exist yet
//!   - The CYBERFENCE_USE_MOCK env var is set
//!   - The named pipe is not available
//!
//! All data structures here are JSON-serializable and match the Svelte
//! TypeScript interfaces in ui/src/lib/types.ts exactly.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

// ── Shared types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentStatus {
    pub protection_status:     String, // "PROTECTED" | "AT_RISK" | "SCANNING" | "DISABLED"
    pub realtime_monitoring:   bool,
    pub scanning_enabled:      bool,
    pub last_scan_time:        Option<String>, // ISO 8601
    pub definitions_version:   String,
    pub definitions_age_hours: u32,
    pub files_monitored_today: u64,
    pub threats_today:         u32,
    pub threats_total:         u32,
    pub agent_version:         String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanHistoryEntry {
    pub id:            String,
    pub scan_type:     String,   // "QUICK_SCAN" | "FULL_SCAN" | "ON_ACCESS"
    pub started_at:    String,
    pub completed_at:  String,
    pub files_scanned: u64,
    pub threats_found: u32,
    pub duration_secs: i64,
    pub status:        String,   // "COMPLETE" | "CANCELLED" | "RUNNING"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatEntry {
    pub id:           String,
    pub detected_at:  String,
    pub path:         String,
    pub verdict:      String,    // "INFECTED" | "SUSPICIOUS"
    pub threat_name:  String,
    pub severity:     String,    // "CRITICAL" | "MEDIUM"
    pub action_taken: String,    // "QUARANTINED" | "LOGGED"
    pub scan_type:    String,
    pub extension:    String,
    pub size_bytes:   Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DefinitionsInfo {
    pub version:      String,
    pub updated_at:   String,
    pub age_hours:    u32,
    pub virus_count:  u64,
    pub status:       String,   // "UP_TO_DATE" | "OUTDATED" | "UPDATING"
}

// ── Mock data builders ────────────────────────────────────────────────────────

fn iso(offset_hours: i64) -> String {
    (Utc::now() - Duration::hours(offset_hours)).to_rfc3339()
}

pub fn mock_status() -> AgentStatus {
    AgentStatus {
        protection_status:     "PROTECTED".into(),
        realtime_monitoring:   true,
        scanning_enabled:      true,
        last_scan_time:        Some(iso(2)),
        definitions_version:   "26481".into(),
        definitions_age_hours: 4,
        files_monitored_today: 1_247,
        threats_today:         0,
        threats_total:         3,
        agent_version:         "0.1.0".into(),
    }
}

pub fn mock_scan_history() -> Vec<ScanHistoryEntry> {
    vec![
        ScanHistoryEntry {
            id:            "s1".into(),
            scan_type:     "QUICK_SCAN".into(),
            started_at:    iso(2),
            completed_at:  iso(1),
            files_scanned: 847,
            threats_found: 0,
            duration_secs: 183,
            status:        "COMPLETE".into(),
        },
        ScanHistoryEntry {
            id:            "s2".into(),
            scan_type:     "FULL_SCAN".into(),
            started_at:    iso(26),
            completed_at:  iso(25),
            files_scanned: 48_391,
            threats_found: 2,
            duration_secs: 1340,
            status:        "COMPLETE".into(),
        },
        ScanHistoryEntry {
            id:            "s3".into(),
            scan_type:     "QUICK_SCAN".into(),
            started_at:    iso(50),
            completed_at:  iso(49),
            files_scanned: 912,
            threats_found: 1,
            duration_secs: 241,
            status:        "COMPLETE".into(),
        },
        ScanHistoryEntry {
            id:            "s4".into(),
            scan_type:     "FULL_SCAN".into(),
            started_at:    iso(170),
            completed_at:  iso(169),
            files_scanned: 47_102,
            threats_found: 0,
            duration_secs: 1148,
            status:        "COMPLETE".into(),
        },
    ]
}

pub fn mock_threats() -> Vec<ThreatEntry> {
    vec![
        ThreatEntry {
            id:           "t1".into(),
            detected_at:  iso(27),
            path:         r"C:\Users\Carlos\Downloads\crack_photoshop.exe".into(),
            verdict:      "INFECTED".into(),
            threat_name:  "Win.Trojan.Generic-9953295-0".into(),
            severity:     "CRITICAL".into(),
            action_taken: "QUARANTINED".into(),
            scan_type:    "FULL_SCAN".into(),
            extension:    "exe".into(),
            size_bytes:   Some(4_234_120),
        },
        ThreatEntry {
            id:           "t2".into(),
            detected_at:  iso(27),
            path:         r"C:\Users\Carlos\Downloads\keygen.dll".into(),
            verdict:      "SUSPICIOUS".into(),
            threat_name:  "Heuristics.Broken.Executable".into(),
            severity:     "MEDIUM".into(),
            action_taken: "LOGGED".into(),
            scan_type:    "FULL_SCAN".into(),
            extension:    "dll".into(),
            size_bytes:   Some(128_000),
        },
        ThreatEntry {
            id:           "t3".into(),
            detected_at:  iso(55),
            path:         r"C:\Users\Carlos\Desktop\invoice_doc.exe".into(),
            verdict:      "INFECTED".into(),
            threat_name:  "Win.Malware.Emotet-9827123-1".into(),
            severity:     "CRITICAL".into(),
            action_taken: "QUARANTINED".into(),
            scan_type:    "ON_ACCESS".into(),
            extension:    "exe".into(),
            size_bytes:   Some(2_048_576),
        },
    ]
}

pub fn mock_definitions() -> DefinitionsInfo {
    DefinitionsInfo {
        version:     "26481".into(),
        updated_at:  iso(4),
        age_hours:   4,
        virus_count: 8_723_142,
        status:      "UP_TO_DATE".into(),
    }
}

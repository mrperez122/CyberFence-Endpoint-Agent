//! Realistic mock data for Phase 1 (no backend connected yet).
//! Phase 2: replace each function with a named pipe call to cf-agent.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};

// ── Shared types (mirror cf-common for the frontend) ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentStatus {
    pub protection_status:    ProtectionStatus,
    pub realtime_monitoring:  bool,
    pub scanning_enabled:     bool,
    pub last_scan_time:       Option<DateTime<Utc>>,
    pub definitions_version:  String,
    pub definitions_age_hours: u32,
    pub files_monitored_today: u64,
    pub threats_today:        u32,
    pub threats_total:        u32,
    pub agent_version:        String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtectionStatus {
    Protected,
    AtRisk,
    Scanning,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanHistoryEntry {
    pub id:            String,
    pub scan_type:     String,   // "QUICK_SCAN" | "FULL_SCAN" | "ON_ACCESS"
    pub started_at:    DateTime<Utc>,
    pub completed_at:  DateTime<Utc>,
    pub files_scanned: u64,
    pub threats_found: u32,
    pub duration_secs: i64,
    pub status:        String,   // "COMPLETE" | "CANCELLED" | "RUNNING"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatEntry {
    pub id:             String,
    pub detected_at:    DateTime<Utc>,
    pub path:           String,
    pub verdict:        String,  // "INFECTED" | "SUSPICIOUS"
    pub threat_name:    String,
    pub severity:       String,  // "CRITICAL" | "HIGH" | "MEDIUM"
    pub action_taken:   String,  // "QUARANTINED" | "LOGGED" | "DELETED"
    pub scan_type:      String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DefinitionsInfo {
    pub version:      String,
    pub updated_at:   DateTime<Utc>,
    pub age_hours:    u32,
    pub virus_count:  u64,
    pub status:       String,   // "UP_TO_DATE" | "OUTDATED" | "UPDATING"
}

// ── Mock data generators ──────────────────────────────────────────────────────

pub fn mock_status() -> AgentStatus {
    AgentStatus {
        protection_status:    ProtectionStatus::Protected,
        realtime_monitoring:  true,
        scanning_enabled:     true,
        last_scan_time:       Some(Utc::now() - Duration::hours(2)),
        definitions_version:  "26481".to_string(),
        definitions_age_hours: 4,
        files_monitored_today: 1_247,
        threats_today:        0,
        threats_total:        3,
        agent_version:        "0.1.0".to_string(),
    }
}

pub fn mock_scan_history() -> Vec<ScanHistoryEntry> {
    let now = Utc::now();
    vec![
        ScanHistoryEntry {
            id:            "s1".to_string(),
            scan_type:     "QUICK_SCAN".to_string(),
            started_at:    now - Duration::hours(2),
            completed_at:  now - Duration::hours(2) + Duration::minutes(3),
            files_scanned: 847,
            threats_found: 0,
            duration_secs: 183,
            status:        "COMPLETE".to_string(),
        },
        ScanHistoryEntry {
            id:            "s2".to_string(),
            scan_type:     "FULL_SCAN".to_string(),
            started_at:    now - Duration::days(1),
            completed_at:  now - Duration::days(1) + Duration::minutes(22),
            files_scanned: 48_391,
            threats_found: 2,
            duration_secs: 1340,
            status:        "COMPLETE".to_string(),
        },
        ScanHistoryEntry {
            id:            "s3".to_string(),
            scan_type:     "QUICK_SCAN".to_string(),
            started_at:    now - Duration::days(2),
            completed_at:  now - Duration::days(2) + Duration::minutes(4),
            files_scanned: 912,
            threats_found: 1,
            duration_secs: 241,
            status:        "COMPLETE".to_string(),
        },
        ScanHistoryEntry {
            id:            "s4".to_string(),
            scan_type:     "FULL_SCAN".to_string(),
            started_at:    now - Duration::days(7),
            completed_at:  now - Duration::days(7) + Duration::minutes(19),
            files_scanned: 47_102,
            threats_found: 0,
            duration_secs: 1148,
            status:        "COMPLETE".to_string(),
        },
    ]
}

pub fn mock_threats() -> Vec<ThreatEntry> {
    let now = Utc::now();
    vec![
        ThreatEntry {
            id:           "t1".to_string(),
            detected_at:  now - Duration::days(1) - Duration::hours(3),
            path:         "C:\\Users\\Carlos\\Downloads\\crack_photoshop.exe".to_string(),
            verdict:      "INFECTED".to_string(),
            threat_name:  "Win.Trojan.Generic-9953295-0".to_string(),
            severity:     "CRITICAL".to_string(),
            action_taken: "QUARANTINED".to_string(),
            scan_type:    "FULL_SCAN".to_string(),
        },
        ThreatEntry {
            id:           "t2".to_string(),
            detected_at:  now - Duration::days(1) - Duration::hours(3) + Duration::minutes(1),
            path:         "C:\\Users\\Carlos\\Downloads\\keygen.dll".to_string(),
            verdict:      "SUSPICIOUS".to_string(),
            threat_name:  "Heuristics.Broken.Executable".to_string(),
            severity:     "MEDIUM".to_string(),
            action_taken: "LOGGED".to_string(),
            scan_type:    "FULL_SCAN".to_string(),
        },
        ThreatEntry {
            id:           "t3".to_string(),
            detected_at:  now - Duration::days(2) - Duration::hours(7),
            path:         "C:\\Users\\Carlos\\Desktop\\invoice_doc.exe".to_string(),
            verdict:      "INFECTED".to_string(),
            threat_name:  "Win.Malware.Emotet-9827123-1".to_string(),
            severity:     "CRITICAL".to_string(),
            action_taken: "QUARANTINED".to_string(),
            scan_type:    "ON_ACCESS".to_string(),
        },
    ]
}

pub fn mock_definitions() -> DefinitionsInfo {
    DefinitionsInfo {
        version:     "26481".to_string(),
        updated_at:  Utc::now() - Duration::hours(4),
        age_hours:   4,
        virus_count: 8_723_142,
        status:      "UP_TO_DATE".to_string(),
    }
}

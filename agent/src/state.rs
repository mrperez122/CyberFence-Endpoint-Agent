//! Shared agent state — a thread-safe, in-memory view of the agent's current
//! status, threat list, and scan history.
//!
//! All components write to this state; the IPC server reads from it.
//! The state is backed by a Mutex<Vec<...>> per collection — simple, correct,
//! and fast enough for MVP volumes (< 10,000 events).

use std::sync::{Mutex, atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering}};

use cf_ipc::protocol::{
    AgentStatusPayload, DefinitionsInfoPayload, ScanHistoryPayload, ThreatPayload,
};
use chrono::Utc;

const MAX_THREATS:  usize = 1_000;
const MAX_HISTORY:  usize = 200;

/// Shared, thread-safe agent state.
pub struct AgentState {
    // Atomic counters — cheaply readable without locking
    pub files_monitored_today: AtomicU64,
    pub threats_today:         AtomicU32,
    pub threats_total:         AtomicU32,
    pub scanning_enabled:      AtomicBool,
    pub monitoring_active:     AtomicBool,

    // Recent data collections — locked briefly on write
    threats:      Mutex<Vec<ThreatPayload>>,
    scan_history: Mutex<Vec<ScanHistoryPayload>>,

    // Definitions metadata
    pub defs_version:   Mutex<String>,
    pub defs_updated:   Mutex<String>,
    pub agent_version:  String,
    pub last_scan_time: Mutex<Option<String>>,
}

impl Default for AgentState {
    fn default() -> Self {
        Self {
            files_monitored_today: AtomicU64::new(0),
            threats_today:         AtomicU32::new(0),
            threats_total:         AtomicU32::new(0),
            scanning_enabled:      AtomicBool::new(true),
            monitoring_active:     AtomicBool::new(true),
            threats:               Mutex::new(Vec::new()),
            scan_history:          Mutex::new(Vec::new()),
            defs_version:          Mutex::new("—".to_string()),
            defs_updated:          Mutex::new(Utc::now().to_rfc3339()),
            agent_version:         env!("CARGO_PKG_VERSION").to_string(),
            last_scan_time:        Mutex::new(None),
        }
    }
}

impl AgentState {
    /// Record a file monitoring event (increments daily counter).
    pub fn record_file_event(&self) {
        self.files_monitored_today.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a detected threat.
    pub fn record_threat(&self, threat: ThreatPayload) {
        self.threats_today.fetch_add(1, Ordering::Relaxed);
        self.threats_total.fetch_add(1, Ordering::Relaxed);

        let mut guard = self.threats.lock().unwrap();
        guard.insert(0, threat);                         // most recent first
        guard.truncate(MAX_THREATS);
    }

    /// Record a completed scan job.
    pub fn record_scan(&self, entry: ScanHistoryPayload) {
        *self.last_scan_time.lock().unwrap() = Some(entry.completed_at.clone());
        let mut guard = self.scan_history.lock().unwrap();
        guard.insert(0, entry);
        guard.truncate(MAX_HISTORY);
    }

    /// Mark a threat as dismissed (removes from the in-memory list).
    pub fn dismiss_threat(&self, id: &str) {
        self.threats.lock().unwrap().retain(|t| t.id != id);
    }

    /// Get recent threats (up to `limit`).
    pub fn get_recent_threats(&self, limit: usize) -> Vec<ThreatPayload> {
        self.threats.lock().unwrap()
            .iter().take(limit).cloned().collect()
    }

    /// Get scan history (up to `limit`).
    pub fn get_scan_history(&self, limit: usize) -> Vec<ScanHistoryPayload> {
        self.scan_history.lock().unwrap()
            .iter().take(limit).cloned().collect()
    }

    /// Build a status payload for the IPC response.
    pub fn to_status_payload(&self) -> AgentStatusPayload {
        let last_scan = self.last_scan_time.lock().unwrap().clone();
        let defs_ver  = self.defs_version.lock().unwrap().clone();
        let defs_upd  = self.defs_updated.lock().unwrap().clone();

        let defs_age_hours = {
            if let Ok(t) = chrono::DateTime::parse_from_rfc3339(&defs_upd) {
                let diff = Utc::now().signed_duration_since(t.with_timezone(&Utc));
                diff.num_hours().max(0) as u32
            } else { 0 }
        };

        let protection_status = if !self.monitoring_active.load(Ordering::Relaxed) {
            "DISABLED"
        } else if defs_age_hours > 24 {
            "AT_RISK"
        } else {
            "PROTECTED"
        };

        AgentStatusPayload {
            protection_status:     protection_status.to_string(),
            realtime_monitoring:   self.monitoring_active.load(Ordering::Relaxed),
            scanning_enabled:      self.scanning_enabled.load(Ordering::Relaxed),
            last_scan_time:        last_scan,
            definitions_version:   defs_ver,
            definitions_age_hours: defs_age_hours,
            files_monitored_today: self.files_monitored_today.load(Ordering::Relaxed),
            threats_today:         self.threats_today.load(Ordering::Relaxed),
            threats_total:         self.threats_total.load(Ordering::Relaxed),
            agent_version:         self.agent_version.clone(),
            engine_version:        None,
        }
    }

    /// Build a definitions info payload.
    pub fn get_definitions_info(&self) -> DefinitionsInfoPayload {
        let ver     = self.defs_version.lock().unwrap().clone();
        let updated = self.defs_updated.lock().unwrap().clone();
        let age     = {
            if let Ok(t) = chrono::DateTime::parse_from_rfc3339(&updated) {
                Utc::now().signed_duration_since(t.with_timezone(&Utc)).num_hours().max(0) as u32
            } else { 0 }
        };
        DefinitionsInfoPayload {
            version:     ver,
            updated_at:  updated,
            age_hours:   age,
            virus_count: 0,
            status:      if age <= 24 { "UP_TO_DATE" } else { "OUTDATED" }.to_string(),
        }
    }
}

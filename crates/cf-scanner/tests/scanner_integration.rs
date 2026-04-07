//! Integration tests for the CyberFence scanning engine.
//!
//! # Test categories
//!
//! 1. **Mock verdict tests** — test ScanVerdict logic without ClamAV
//! 2. **Scan logger tests** — test JSONL output format
//! 3. **Quarantine tests** — test AES encryption + restore roundtrip
//! 4. **Live ClamAV tests** — skipped if clamscan not installed
//!
//! # How to test with EICAR (safe malware test file)
//!
//! The EICAR test file is a standard, universally-detected test string
//! that all AV engines recognize as a "safe" simulated threat.
//! It is NOT real malware — it is safe to create and scan.
//!
//! EICAR string (ASCII, safe to embed in source code):
//! ```text
//! X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
//! ```
//!
//! Run live ClamAV tests:
//!   CYBERFENCE_TEST_LIVE=1 cargo test --test scanner_integration -- --nocapture
//!
//! # Running on CI (no ClamAV installed)
//!
//! All live tests are skipped when ClamAV is not present.
//! Unit-level logic tests always run.

use std::path::PathBuf;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::mpsc;
use tokio::time::timeout;

use cf_common::{
    events::{FileEvent, FileEventKind, ScanReadiness},
    scan::ScanVerdict,
};
use cf_config::AgentConfig;
use cf_scanner::{clamav, engine::ScanEngine, quarantine, scan_logger::ScanLogger};
use chrono::Utc;
use uuid::Uuid;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// EICAR standard test string — detected by all AV engines as "Eicar-Signature"
/// This is NOT malware. It is safe to create and harmless.
const EICAR_STRING: &[u8] =
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

fn mock_file_event(path: PathBuf) -> FileEvent {
    let size = std::fs::metadata(&path).ok().map(|m| m.len());
    FileEvent {
        id:             Uuid::new_v4(),
        timestamp:      Utc::now(),
        extension:      path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase(),
        old_path:       None,
        watch_root:     path.parent().unwrap_or(&path).to_path_buf(),
        scan_readiness: ScanReadiness::PendingScan,
        kind:           FileEventKind::Created,
        size_bytes:     size,
        path,
    }
}

fn has_clamscan() -> bool {
    let config = AgentConfig::default();
    clamav::find_clamscan(&config.scanner).is_some()
}

fn live_tests_enabled() -> bool {
    std::env::var("CYBERFENCE_TEST_LIVE").is_ok()
}

// ── 1. Verdict logic tests (no ClamAV required) ───────────────────────────────

#[test]
fn clean_verdict_is_not_a_threat() {
    assert!(!ScanVerdict::Clean.is_threat());
    assert_eq!(ScanVerdict::Clean.label(), "CLEAN");
    assert_eq!(
        ScanVerdict::Clean.severity(),
        cf_common::events::Severity::Info
    );
}

#[test]
fn infected_verdict_is_a_threat() {
    let v = ScanVerdict::Infected("Eicar-Signature".to_string());
    assert!(v.is_threat());
    assert_eq!(v.label(), "INFECTED");
    assert_eq!(
        v.severity(),
        cf_common::events::Severity::Critical
    );
}

#[test]
fn suspicious_verdict_is_a_threat() {
    let v = ScanVerdict::Suspicious("Heuristics.Broken.Executable".to_string());
    assert!(v.is_threat());
    assert_eq!(v.label(), "SUSPICIOUS");
    assert_eq!(
        v.severity(),
        cf_common::events::Severity::Medium
    );
}

#[test]
fn skipped_verdict_is_not_a_threat() {
    let v = ScanVerdict::Skipped("File too large".to_string());
    assert!(!v.is_threat());
    assert_eq!(v.label(), "SKIPPED");
}

#[test]
fn error_verdict_is_not_a_threat() {
    let v = ScanVerdict::Error("Timeout".to_string());
    assert!(!v.is_threat());
    assert_eq!(v.label(), "ERROR");
}

// ── 2. Scan logger tests ──────────────────────────────────────────────────────

#[test]
fn scan_logger_writes_jsonl_for_infected() {
    let dir = tempdir().unwrap();
    let logger = ScanLogger::new(dir.path().to_path_buf());

    let result = cf_common::ScanResult {
        id:                  Uuid::new_v4(),
        scanned_at:          Utc::now(),
        path:                PathBuf::from(r"C:\Downloads\malware.exe"),
        size_bytes:          Some(2048),
        triggered_by_event:  Some(Uuid::new_v4()),
        duration_ms:         250,
        verdict:             ScanVerdict::Infected("Win.Trojan.Test".to_string()),
        definitions_version: None,
    };

    logger.write(&result, "QUARANTINED").unwrap();

    let log_content = std::fs::read_to_string(logger.today_log_path()).unwrap();
    let record: serde_json::Value = serde_json::from_str(log_content.trim()).unwrap();

    assert_eq!(record["verdict"], "INFECTED");
    assert_eq!(record["threat_name"], "Win.Trojan.Test");
    assert_eq!(record["severity"], "CRITICAL");
    assert_eq!(record["action"], "QUARANTINED");
    assert_eq!(record["extension"], "exe");
    assert_eq!(record["size_bytes"], 2048);
    assert_eq!(record["duration_ms"], 250);
}

#[test]
fn scan_logger_writes_jsonl_for_clean() {
    let dir    = tempdir().unwrap();
    let logger = ScanLogger::new(dir.path().to_path_buf());

    let result = cf_common::ScanResult {
        id:                  Uuid::new_v4(),
        scanned_at:          Utc::now(),
        path:                PathBuf::from("/home/user/Downloads/safe.pdf"),
        size_bytes:          Some(512),
        triggered_by_event:  None,
        duration_ms:         100,
        verdict:             ScanVerdict::Clean,
        definitions_version: None,
    };

    logger.write(&result, "LOGGED").unwrap();

    let content = std::fs::read_to_string(logger.today_log_path()).unwrap();
    let record: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    assert_eq!(record["verdict"], "CLEAN");
    assert_eq!(record["severity"], "INFO");
    assert_eq!(record["action"], "LOGGED");
    // triggered_by_event should be absent (None was passed)
    assert!(record["triggered_by_event"].is_null());
}

// ── 3. Quarantine tests ───────────────────────────────────────────────────────

#[test]
fn quarantine_encrypts_and_deletes_original() {
    let dir      = tempdir().unwrap();
    let original = dir.path().join("infected.exe");
    std::fs::write(&original, b"MZ fake malware").unwrap();

    let record = quarantine::quarantine_file(&original, "Win.Test").unwrap();

    // Original must be gone
    assert!(!original.exists(), "original file should be deleted");
    // Vault file must exist and have .cfq extension
    assert!(record.vault_path.exists(), "vault file should exist");
    assert_eq!(record.vault_path.extension().and_then(|e| e.to_str()), Some("cfq"));

    // Vault content must NOT equal original plaintext
    let vault_bytes = std::fs::read(&record.vault_path).unwrap();
    assert_ne!(vault_bytes, b"MZ fake malware", "vault should be encrypted, not plaintext");
    // Must be longer (has nonce + GCM auth tag)
    assert!(vault_bytes.len() > b"MZ fake malware".len());
}

#[test]
fn quarantine_restore_roundtrip() {
    let dir      = tempdir().unwrap();
    let original = dir.path().join("test.docx");
    let content  = b"This is a secret document content 12345";
    std::fs::write(&original, content).unwrap();

    let record = quarantine::quarantine_file(&original, "Test.Threat").unwrap();
    assert!(!original.exists());

    quarantine::restore_file(&record).unwrap();
    assert!(original.exists(), "file should be restored");

    let restored = std::fs::read(&original).unwrap();
    assert_eq!(restored, content, "restored content must match original exactly");
    assert!(!record.vault_path.exists(), "vault should be deleted after restore");
}

#[test]
fn quarantined_file_vault_has_correct_nonce_prefix() {
    let dir      = tempdir().unwrap();
    let original = dir.path().join("malware.dll");
    std::fs::write(&original, b"AAAAAAAAAAAAAAAA").unwrap();

    let record       = quarantine::quarantine_file(&original, "Test").unwrap();
    let vault_bytes  = std::fs::read(&record.vault_path).unwrap();

    // First 12 bytes are the AES-GCM nonce, must exist
    assert!(vault_bytes.len() >= 12, "vault must have at least 12 bytes for nonce");
}

// ── 4. Live ClamAV tests (skipped if clamscan not installed) ─────────────────

#[tokio::test]
async fn live_scan_eicar_file_returns_infected() {
    if !has_clamscan() || !live_tests_enabled() {
        println!("SKIPPED: clamscan not found or CYBERFENCE_TEST_LIVE not set");
        println!("To run: CYBERFENCE_TEST_LIVE=1 cargo test --test scanner_integration");
        return;
    }

    let dir  = tempdir().unwrap();
    let path = dir.path().join("eicar.com");
    std::fs::write(&path, EICAR_STRING).unwrap();

    let config = AgentConfig::default();
    let result = ScanEngine::scan_file_now(&path, &config).await;

    println!("Verdict: {:?}", result.verdict);

    assert!(
        matches!(result.verdict, ScanVerdict::Infected(_)),
        "EICAR file must be detected as INFECTED, got: {:?}",
        result.verdict
    );

    if let ScanVerdict::Infected(name) = &result.verdict {
        assert!(
            name.contains("Eicar") || name.contains("EICAR") || name.contains("eicar"),
            "Virus name should contain 'Eicar', got: {}",
            name
        );
    }
}

#[tokio::test]
async fn live_scan_clean_file_returns_clean() {
    if !has_clamscan() || !live_tests_enabled() {
        println!("SKIPPED: set CYBERFENCE_TEST_LIVE=1 to run live tests");
        return;
    }

    let dir  = tempdir().unwrap();
    let path = dir.path().join("clean.txt");
    std::fs::write(&path, b"Hello, this is a clean file with no malware.").unwrap();

    let config = AgentConfig::default();
    let result = ScanEngine::scan_file_now(&path, &config).await;

    assert_eq!(
        result.verdict,
        ScanVerdict::Clean,
        "Clean file should return CLEAN, got: {:?}",
        result.verdict
    );
}

#[tokio::test]
async fn live_scan_via_event_channel() {
    if !has_clamscan() || !live_tests_enabled() {
        println!("SKIPPED: set CYBERFENCE_TEST_LIVE=1 to run live tests");
        return;
    }

    let dir  = tempdir().unwrap();
    let path = dir.path().join("eicar_channel.com");
    std::fs::write(&path, EICAR_STRING).unwrap();

    let config           = AgentConfig::default();
    let (event_tx, event_rx)   = mpsc::channel(10);
    let (result_tx, mut result_rx) = mpsc::channel(10);

    // Start the scan engine
    let engine  = ScanEngine::new(config, event_rx, result_tx);
    tokio::spawn(engine.run());

    // Send a file event for the EICAR file
    let event = mock_file_event(path);
    event_tx.send(event).await.unwrap();

    // Wait for the scan result
    let result = timeout(Duration::from_secs(10), result_rx.recv())
        .await
        .expect("timeout waiting for scan result")
        .expect("channel closed");

    assert!(
        matches!(result.verdict, ScanVerdict::Infected(_)),
        "EICAR via event channel should be INFECTED, got: {:?}",
        result.verdict
    );
}

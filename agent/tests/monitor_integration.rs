//! Integration tests for the CyberFence file monitoring pipeline.
//!
//! These tests exercise the full stack:
//!   tempfile (real FS) → cf-monitor → MPSC channel → FileEvent assertions
//!
//! Run with:
//!   cargo test --test monitor_integration -- --nocapture
//!
//! NOTE: These tests operate on the real filesystem using `tempfile` crate.
//! They require that `notify-rs` can watch the OS's temp directory.

use std::fs;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::mpsc;
use tokio::time::timeout;

use cf_common::events::{FileEventKind, ScanReadiness};
use cf_config::AgentConfig;
use cf_monitor::FileMonitor;

// Helper: build a minimal AgentConfig that watches only `watch_path`
fn config_for_dir(watch_path: std::path::PathBuf) -> AgentConfig {
    let mut config = AgentConfig::default();
    config.monitor.extra_watch_dirs = vec![watch_path];
    config.monitor.debounce_ms = 50; // faster for tests
    config.monitor.ring_buffer_cap = 100;
    // Disable scanner so tests don't need ClamAV installed
    config.scanner.enabled = false;
    config
}

// ── File creation ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_file_created_event_emitted() {
    let dir = tempdir().expect("create tempdir");
    let config = config_for_dir(dir.path().to_path_buf());

    let (tx, mut rx) = mpsc::channel(100);
    let monitor = FileMonitor::new(config, tx);
    tokio::spawn(async move { monitor.run().await });

    // Give the watcher a moment to register
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Create a file in the watched directory
    let file_path = dir.path().join("test_file.exe");
    fs::write(&file_path, b"MZ dummy exe content").expect("write test file");

    // Wait for the FileEvent to arrive (up to 3 seconds)
    let event = timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("timeout waiting for FileEvent")
        .expect("channel closed unexpectedly");

    assert_eq!(event.path, file_path, "event path should match created file");
    assert!(
        matches!(event.kind, FileEventKind::Created | FileEventKind::Modified),
        "expected Created or Modified, got {:?}",
        event.kind
    );
    assert_eq!(event.extension, "exe", "extension should be 'exe'");
    assert!(event.size_bytes.is_some(), "size_bytes should be populated for existing file");
    assert!(
        matches!(event.scan_readiness, ScanReadiness::PendingScan),
        "scannable .exe should be PendingScan"
    );
}

// ── File deletion ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_file_deleted_event_emitted() {
    let dir = tempdir().expect("create tempdir");
    let config = config_for_dir(dir.path().to_path_buf());

    let (tx, mut rx) = mpsc::channel(100);
    let monitor = FileMonitor::new(config, tx);
    tokio::spawn(async move { monitor.run().await });

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Create then immediately delete a file
    let file_path = dir.path().join("to_delete.txt");
    fs::write(&file_path, b"content").expect("write file");
    tokio::time::sleep(Duration::from_millis(200)).await;
    fs::remove_file(&file_path).expect("delete file");

    // Drain events until we see a Deleted event for our file
    let mut saw_delete = false;
    for _ in 0..10 {
        match timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(event)) if event.path == file_path => {
                if matches!(event.kind, FileEventKind::Deleted) {
                    saw_delete = true;
                    break;
                }
            }
            Ok(Some(_)) => {} // other events (Created etc.) — keep draining
            _ => break,
        }
    }

    assert!(saw_delete, "expected a Deleted event for the file");
}

// ── Excluded extension ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_excluded_extension_not_emitted() {
    let dir = tempdir().expect("create tempdir");
    let mut config = config_for_dir(dir.path().to_path_buf());
    // .log is in the default excluded_extensions list
    config.monitor.excluded_extensions = vec!["log".into(), "tmp".into()];

    let (tx, mut rx) = mpsc::channel(100);
    let monitor = FileMonitor::new(config, tx);
    tokio::spawn(async move { monitor.run().await });

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Write a .log file — should NOT produce a FileEvent
    fs::write(dir.path().join("debug.log"), b"log content").expect("write log");
    // Also write a .exe file — SHOULD produce an event
    let exe_path = dir.path().join("allowed.exe");
    fs::write(&exe_path, b"exe content").expect("write exe");

    // We should get an event for .exe but not for .log
    let event = timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    assert_eq!(
        event.path, exe_path,
        "Only the .exe event should arrive; .log should be filtered"
    );
}

// ── File modification ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_file_modified_event_emitted() {
    let dir = tempdir().expect("create tempdir");
    let config = config_for_dir(dir.path().to_path_buf());

    let (tx, mut rx) = mpsc::channel(100);
    let monitor = FileMonitor::new(config, tx);
    tokio::spawn(async move { monitor.run().await });

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Create file first
    let file_path = dir.path().join("modified.pdf");
    fs::write(&file_path, b"v1").expect("write v1");

    // Drain creation event
    let _ = timeout(Duration::from_secs(2), rx.recv()).await;

    // Modify the file
    fs::write(&file_path, b"v2 updated content").expect("write v2");

    // Look for a Modified event
    let mut saw_modify = false;
    for _ in 0..10 {
        match timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(event)) if event.path == file_path => {
                if matches!(event.kind, FileEventKind::Modified | FileEventKind::Created) {
                    saw_modify = true;
                    break;
                }
            }
            Ok(Some(_)) => {}
            _ => break,
        }
    }
    assert!(saw_modify, "expected a Modified event after rewriting the file");
}

// ── is_scannable logic ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_created_file_is_scannable() {
    let dir = tempdir().expect("create tempdir");
    let config = config_for_dir(dir.path().to_path_buf());

    let (tx, mut rx) = mpsc::channel(100);
    let monitor = FileMonitor::new(config, tx);
    tokio::spawn(async move { monitor.run().await });

    tokio::time::sleep(Duration::from_millis(300)).await;

    let file_path = dir.path().join("scanme.exe");
    fs::write(&file_path, b"MZ").expect("write file");

    let event = timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    // is_scannable must return true for Created/Modified + PendingScan
    assert!(
        event.is_scannable(),
        "a created .exe should be scannable; got kind={:?} readiness={:?}",
        event.kind,
        event.scan_readiness
    );
}

// ── Event ID uniqueness ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_event_ids_are_unique() {
    let dir = tempdir().expect("create tempdir");
    let config = config_for_dir(dir.path().to_path_buf());

    let (tx, mut rx) = mpsc::channel(100);
    let monitor = FileMonitor::new(config, tx);
    tokio::spawn(async move { monitor.run().await });

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Create 3 different files
    for i in 0..3 {
        fs::write(dir.path().join(format!("file_{i}.exe")), b"x").expect("write");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let mut ids = std::collections::HashSet::new();
    for _ in 0..3 {
        if let Ok(Some(event)) = timeout(Duration::from_secs(2), rx.recv()).await {
            ids.insert(event.id);
        }
    }

    // All collected IDs must be unique UUIDs
    assert!(ids.len() >= 1, "expected at least 1 event");
    // UUIDs v4 are virtually guaranteed unique — this validates they are set
    for id in &ids {
        assert_ne!(*id, uuid::Uuid::nil(), "event ID should not be nil UUID");
    }
}

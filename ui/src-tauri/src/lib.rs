//! CyberFence Endpoint UI — Tauri 2 backend
//!
//! # Architecture
//!
//! ```text
//! Svelte invoke("get_status")
//!     ↓  Tauri IPC (secure in-process WebView bridge)
//! #[tauri::command] handler (commands.rs)
//!     ↓  reads from scan log files OR calls agent_status module
//!     ↓  Phase 3: \\.\pipe\CyberFenceAgent named pipe
//! cf-agent daemon
//! ```
//!
//! # How the UI reads log/results (Phase 1–2)
//!
//! The dashboard reads the structured JSONL files written by cf-scanner:
//! - `%APPDATA%\CyberFence\logs\scans-YYYY-MM-DD.jsonl`  (scan results)
//! - `%APPDATA%\CyberFence\logs\agent-YYYY-MM-DD.jsonl`  (file events)
//!
//! This requires NO named pipe connection — the UI can display real data
//! the moment the agent writes it. Phase 3 adds live push events via IPC.

mod commands;
mod log_reader;
mod mock;
mod tray;

use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            tray::setup_tray(app)?;

            // In release mode: start hidden; user opens via tray click
            // In debug mode: show immediately so developers see the UI
            if let Some(window) = app.get_webview_window("main") {
                #[cfg(not(debug_assertions))]
                window.hide().ok();
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::get_scan_history,
            commands::get_threats,
            commands::get_definitions_info,
            commands::run_quick_scan,
            commands::run_full_scan,
            commands::dismiss_threat,
        ])
        .run(tauri::generate_context!())
        .expect("error while running CyberFence application");
}

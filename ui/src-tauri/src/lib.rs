//! CyberFence Endpoint UI — Tauri 2 backend
//!
//! # Responsibilities
//!
//! 1. System tray icon — status-colored indicator + context menu
//! 2. Window management — show/hide the dashboard on tray click
//! 3. IPC commands — bridge between Svelte frontend and the cf-agent service
//! 4. Mock data — Phase 1: returns realistic test data; Phase 2: connects to named pipe
//!
//! # IPC Architecture
//!
//! ```text
//! Svelte invoke("get_status")
//!     ↓  Tauri IPC (secure WebView bridge)
//! #[tauri::command] fn get_status()
//!     ↓  Phase 2: connects to \\.\pipe\CyberFenceAgent
//! cf-agent daemon  (ScanResult, ScanSummary, FileEvent)
//! ```

mod commands;
mod mock;
mod tray;

use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            // Build the system tray
            tray::setup_tray(app)?;

            // Hide window on startup — user opens via tray click
            if let Some(window) = app.get_webview_window("main") {
                #[cfg(not(debug_assertions))]
                window.hide().ok();
            }

            Ok(())
        })
        // Register all IPC command handlers
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::get_scan_history,
            commands::get_threats,
            commands::run_quick_scan,
            commands::run_full_scan,
            commands::get_definitions_info,
        ])
        .run(tauri::generate_context!())
        .expect("error while running CyberFence application");
}

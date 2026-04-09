//! CyberFence Endpoint UI — Tauri 2 backend

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
            // Set up system tray
            tray::setup_tray(app)?;

            // Always show the window on launch — user can close to tray
            if let Some(window) = app.get_webview_window("main") {
                window.show().ok();
                window.set_focus().ok();
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

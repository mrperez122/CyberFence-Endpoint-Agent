//! System tray setup and event handling.
//!
//! The tray icon shows protection status:
//!   Green shield  = Protected
//!   Yellow shield = At risk / outdated definitions
//!   Red shield    = Disabled / error
//!
//! Left-click:  show/hide the dashboard window
//! Right-click: context menu → Open Dashboard | Quick Scan | Quit

use tauri::{
    App, Emitter, Manager,
    menu::{Menu, MenuItem},
    tray::{TrayIconBuilder, TrayIconEvent},
};

pub fn setup_tray(app: &mut App) -> tauri::Result<()> {
    // Build context menu
    let open_item  = MenuItem::with_id(app, "open",       "Open Dashboard", true, None::<&str>)?;
    let scan_item  = MenuItem::with_id(app, "quick_scan", "Quick Scan",     true, None::<&str>)?;
    let sep        = tauri::menu::PredefinedMenuItem::separator(app)?;
    let quit_item  = MenuItem::with_id(app, "quit",       "Quit CyberFence",true, None::<&str>)?;

    let menu = Menu::with_items(app, &[&open_item, &scan_item, &sep, &quit_item])?;

    // Build tray icon
    TrayIconBuilder::with_id("cf-tray")
        .tooltip("CyberFence Endpoint — Protected")
        .menu(&menu)
        .menu_on_left_click(false) // left click = toggle window, not menu
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => {
                toggle_window(app);
            }
            "quick_scan" => {
                // Emit event to frontend to start scan
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.emit("trigger_quick_scan", ());
                }
            }
            "quit" => {
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            // Left click toggles the dashboard window
            if let TrayIconEvent::Click { .. } = event {
                toggle_window(tray.app_handle());
            }
        })
        .build(app)?;

    Ok(())
}

fn toggle_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        if window.is_visible().unwrap_or(false) {
            window.hide().ok();
        } else {
            window.show().ok();
            window.set_focus().ok();
        }
    }
}

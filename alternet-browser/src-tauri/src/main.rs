// Tauri requires this on Windows
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    alternet_browser_lib::run();
}

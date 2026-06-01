//! # AlterNet Browser — Tauri v2 Backend
//!
//! Tarayıcı arka ucu: P2P içerik çekme, yayınlama, kimlik yönetimi.
//!
//! **Manifesto VI:** "Tarayıcıyı aç, adresi yaz, içeriği gör."
//! **Manifesto I:** Hesap yok, sunucu yok — her şey P2P.

mod commands;
mod state;

use state::BrowserState;
use tauri::Manager;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            // Global state başlat — tokio runtime arkaplanda çalışır
            let state = BrowserState::new();
            app.manage(state);

            // alter:// protokol handler'ını kaydet
            // Bu handler alter://KEY[/subpath] isteklerini karşılar
            // İçerik yerel block store'dan servis edilir
            Ok(())
        })
        .register_uri_scheme_protocol("alter", |ctx, req| {
            commands::browse::handle_alter_protocol(ctx, req)
        })
        .invoke_handler(tauri::generate_handler![
            commands::browse::fetch_site,
            commands::browse::get_site_status,
            commands::publish::publish_site,
            commands::publish::validate_publish_folder,
            commands::identity::get_identity,
            commands::identity::generate_identity,
            commands::pin::pin_site,
            commands::pin::list_pins,
            commands::pin::unpin_site,
            commands::browse::resolve_name,
        ])
        .run(tauri::generate_context!())
        .expect("AlterNet Browser başlatılamadı");
}

//! Kimlik yönetimi IPC komutları.

use crate::state::BrowserState;
use alternet_core::identity::{
    load_or_generate_keypair, pubkey_to_alter_uri, pubkey_to_hex,
};
use serde::Serialize;
use std::path::PathBuf;
use tauri::State;

#[derive(Serialize)]
pub struct IdentityInfo {
    pub alter_uri: String,
    pub peer_id: String,
    pub pubkey_hex: String,
    pub keyfile: String,
}

/// Mevcut kimliği döndür (yoksa oluştur).
///
/// Manifesto I: Hesap yok, kayıt yok. Kimlik yerel Ed25519 anahtar çiftidir.
#[tauri::command]
pub fn get_identity(state: State<'_, BrowserState>) -> Result<IdentityInfo, String> {
    let keyfile = {
        let inner = state.inner.lock().unwrap();
        inner.config.keyfile_path()
    };

    let keypair =
        load_or_generate_keypair(&keyfile).map_err(|e| format!("Keypair yüklenemedi: {e}"))?;

    let pubkey_bytes = keypair.public().encode_protobuf();
    let alter_uri = pubkey_to_alter_uri(&pubkey_bytes);
    let pubkey_hex = pubkey_to_hex(&pubkey_bytes);
    let peer_id = alternet_core::libp2p::PeerId::from(keypair.public()).to_string();

    Ok(IdentityInfo {
        alter_uri,
        peer_id,
        pubkey_hex,
        keyfile: keyfile.to_string_lossy().to_string(),
    })
}

/// Yeni kimlik oluştur (mevcut varsa hata).
#[tauri::command]
pub fn generate_identity(
    output: Option<String>,
    state: State<'_, BrowserState>,
) -> Result<IdentityInfo, String> {
    let keyfile = output
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let inner = state.inner.lock().unwrap();
            inner.config.keyfile_path()
        });

    if keyfile.exists() {
        return Err(format!(
            "Anahtar dosyası zaten mevcut: {}",
            keyfile.display()
        ));
    }

    let keypair =
        load_or_generate_keypair(&keyfile).map_err(|e| format!("Oluşturulamadı: {e}"))?;

    let pubkey_bytes = keypair.public().encode_protobuf();
    let alter_uri = pubkey_to_alter_uri(&pubkey_bytes);
    let pubkey_hex = pubkey_to_hex(&pubkey_bytes);
    let peer_id = alternet_core::libp2p::PeerId::from(keypair.public()).to_string();

    Ok(IdentityInfo {
        alter_uri,
        peer_id,
        pubkey_hex,
        keyfile: keyfile.to_string_lossy().to_string(),
    })
}

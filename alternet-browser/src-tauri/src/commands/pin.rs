//! Pin / seed yönetimi IPC komutları.

use crate::state::BrowserState;
use alternet_core::replication::{PinRecord, PinStore};
use alternet_core::types::Cid;
use serde::Serialize;
use tauri::State;

#[derive(Serialize, Clone)]
pub struct PinInfo {
    pub root_cid: String,
    pub author_pubkey_hex: String,
    pub label: Option<String>,
    pub pinned_at: u64,
    pub block_count: usize,
}

/// Bir siteyi pin'le (yeniden barındır).
///
/// Manifesto II: "Ziyaretçi değer verdiği siteyi yeniden barındırabilir —
/// ilgi = replikasyon = erişilebilirlik."
#[tauri::command]
pub async fn pin_site(
    uri: String,
    label: Option<String>,
    state: State<'_, BrowserState>,
) -> Result<String, String> {
    use alternet_core::identity::{alter_uri_to_pubkey, pubkey_to_hex};

    let pubkey_bytes =
        alter_uri_to_pubkey(&uri).map_err(|e| format!("Geçersiz URI: {e}"))?;
    let pubkey_hex = pubkey_to_hex(&pubkey_bytes);

    // Mevcut çekilmiş içerik varsa pin ekle
    let data_dir = {
        let inner = state.inner.lock().unwrap();
        inner.config.data_dir.clone()
    };

    let pin_path = data_dir.join("pins.cbor");
    let mut pins = if pin_path.exists() {
        let bytes = std::fs::read(&pin_path).map_err(|e| e.to_string())?;
        let list: Vec<PinRecord> = ciborium::from_reader(bytes.as_slice())
            .map_err(|e| format!("Pin yüklenemedi: {e}"))?;
        let mut ps = PinStore::in_memory();
        for r in list {
            ps.add(r);
        }
        ps
    } else {
        PinStore::in_memory()
    };

    // Boş pin kaydı oluştur (bloklar fetch sonrası doldurulur)
    let placeholder_cid = Cid::from_data(pubkey_bytes.as_slice());
    if !pins.contains(&placeholder_cid) {
        let record = PinRecord::new(
            placeholder_cid.clone(),
            pubkey_hex.clone(),
            label.clone(),
            vec![placeholder_cid],
        );
        pins.add(record);

        // Diske kaydet
        let list: Vec<&PinRecord> = pins.list();
        let mut buf = Vec::new();
        ciborium::into_writer(&list, &mut buf).map_err(|e| e.to_string())?;
        if let Some(parent) = pin_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&pin_path, &buf).map_err(|e| e.to_string())?;
    }

    Ok(format!("Pin eklendi: {uri}"))
}

/// Tüm pinlenmiş siteleri listele.
#[tauri::command]
pub fn list_pins(state: State<'_, BrowserState>) -> Vec<PinInfo> {
    let data_dir = {
        let inner = state.inner.lock().unwrap();
        inner.config.data_dir.clone()
    };

    let pin_path = data_dir.join("pins.cbor");
    if !pin_path.exists() {
        return Vec::new();
    }

    let bytes = match std::fs::read(&pin_path) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };

    let list: Vec<PinRecord> = match ciborium::from_reader(bytes.as_slice()) {
        Ok(l) => l,
        Err(_) => return Vec::new(),
    };

    list.iter()
        .map(|r| PinInfo {
            root_cid: r.root_cid.to_hex(),
            author_pubkey_hex: r.author_pubkey_hex.clone(),
            label: r.label.clone(),
            pinned_at: r.pinned_at,
            block_count: r.block_cids.len(),
        })
        .collect()
}

/// Pin kaldır.
#[tauri::command]
pub fn unpin_site(uri: String, state: State<'_, BrowserState>) -> Result<(), String> {
    use alternet_core::identity::{alter_uri_to_pubkey, pubkey_to_hex};

    let pubkey_bytes =
        alter_uri_to_pubkey(&uri).map_err(|e| format!("Geçersiz URI: {e}"))?;
    let pubkey_hex = pubkey_to_hex(&pubkey_bytes);

    let data_dir = {
        let inner = state.inner.lock().unwrap();
        inner.config.data_dir.clone()
    };

    let pin_path = data_dir.join("pins.cbor");
    if !pin_path.exists() {
        return Ok(());
    }

    let bytes = std::fs::read(&pin_path).map_err(|e| e.to_string())?;
    let mut list: Vec<PinRecord> = ciborium::from_reader(bytes.as_slice())
        .map_err(|e| format!("Pin yüklenemedi: {e}"))?;

    list.retain(|r| r.author_pubkey_hex != pubkey_hex);

    let mut buf = Vec::new();
    ciborium::into_writer(&list, &mut buf).map_err(|e| e.to_string())?;
    std::fs::write(&pin_path, &buf).map_err(|e| e.to_string())?;

    Ok(())
}

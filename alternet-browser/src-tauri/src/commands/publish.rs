//! Site yayınlama IPC komutu.

use crate::state::BrowserState;
use alternet_core::{
    config::AlterNetConfig,
    content::{FsBlockStore, build_dag, collect_all_cids},
    identity::{load_or_generate_keypair, pubkey_to_alter_uri, pubkey_to_hex},
    network::spawn_node,
    publish::{create_manifest, serialize_manifest},
    types::ManifestMeta,
};
use serde::Serialize;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tauri::{AppHandle, Emitter, State};

#[derive(Serialize)]
pub struct PublishResult {
    pub alter_uri: String,
    pub pubkey_hex: String,
    pub block_count: usize,
    pub title: Option<String>,
}

/// Bir klasörü AlterNet'e yayınla.
///
/// Manifesto VII: Her manifest Ed25519 ile imzalanır — imzasız yayın yoktur.
/// Manifesto I: Merkezi sunucu yok — DHT'ye doğrudan yayınlanır.
#[tauri::command]
pub async fn publish_site(
    path: String,
    title: Option<String>,
    description: Option<String>,
    app: AppHandle,
    state: State<'_, BrowserState>,
) -> Result<PublishResult, String> {
    let site_path = PathBuf::from(&path);
    if !site_path.exists() {
        return Err(format!("Klasör bulunamadı: {path}"));
    }

    let data_dir = {
        let inner = state.inner.lock().unwrap();
        inner.config.data_dir.clone()
    };

    let config = AlterNetConfig {
        data_dir: data_dir.clone(),
        mdns_enabled: true,
        ..Default::default()
    };

    let keyfile = config.keyfile_path();
    let keypair =
        load_or_generate_keypair(&keyfile).map_err(|e| format!("Keypair: {e}"))?;

    let pubkey_bytes = keypair.public().encode_protobuf();
    let pubkey_hex = pubkey_to_hex(&pubkey_bytes);
    let alter_uri = pubkey_to_alter_uri(&pubkey_bytes);

    let store = Arc::new(
        FsBlockStore::new(data_dir.join("blocks"), 0)
            .await
            .map_err(|e| format!("Store: {e}"))?,
    );

    // DAG oluştur
    let root_cid = build_dag(&*store, &site_path)
        .await
        .map_err(|e| format!("DAG oluşturulamadı: {e}"))?;

    let all_cids = collect_all_cids(&*store, &root_cid)
        .await
        .map_err(|e| format!("CID toplama: {e}"))?;

    let block_count = all_cids.len();

    // Manifest imzala
    let metadata = ManifestMeta {
        title: title.clone(),
        description,
        mime_type: Some("text/html".into()),
        tags: Vec::new(),
        encrypted: false,
    };

    let manifest = create_manifest(root_cid, &keypair, 1, metadata)
        .map_err(|e| format!("Manifest: {e}"))?;
    let manifest_bytes =
        serialize_manifest(&manifest).map_err(|e| format!("Serialization: {e}"))?;

    // Node başlat ve yayınla
    let node = spawn_node(keypair, config, Arc::clone(&store))
        .await
        .map_err(|e| format!("Node: {e}"))?;

    node.listen_on(0).await.map_err(|e| format!("Listen: {e}"))?;

    // DHT bootstrap
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Manifest'i DHT'ye kaydet
    tokio::time::timeout(
        Duration::from_secs(30),
        node.put_manifest(&pubkey_hex, manifest_bytes),
    )
    .await
    .map_err(|_| "Manifest yayınlama zaman aşımı".to_string())?
    .map_err(|e| format!("Manifest yayınlanamadı: {e}"))?;

    // Blokları duyur
    for cid in &all_cids {
        tokio::time::timeout(Duration::from_secs(10), node.start_providing(cid))
            .await
            .ok();
    }

    // Başarı eventi gönder
    let _ = app.emit("site-published", &alter_uri);

    // Node'u state'e kaydet (Ctrl+C'ye kadar servis sürdürülsün)
    {
        let mut inner = state.inner.lock().unwrap();
        inner.node = Some(Arc::new(node));
        inner.store = Some(Arc::clone(&store));
    }

    Ok(PublishResult {
        alter_uri,
        pubkey_hex,
        block_count,
        title,
    })
}

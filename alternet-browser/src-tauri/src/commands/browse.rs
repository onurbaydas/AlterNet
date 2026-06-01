//! İçerik çekme, alter:// protokol handler ve isim çözümleme.

use crate::state::{BrowserState, FetchStatus};
use alternet_core::{
    config::AlterNetConfig,
    content::{BlockStore as _, FsBlockStore, cbor_decode, extract_dag},
    identity::{alter_uri_to_pubkey, load_or_generate_keypair, pubkey_to_alter_uri, pubkey_to_hex},
    network::spawn_node,
    publish::{deserialize_manifest, verify_manifest},
    types::DagNode,
};
use serde::Serialize;
use std::{collections::VecDeque, path::PathBuf, sync::Arc, time::Duration};
use tauri::{AppHandle, Emitter, Manager, State};

// ═══════════════════════════════════════════════
// alter:// Protokol Handler
// ═══════════════════════════════════════════════

/// Tauri `alter://` custom protocol handler.
///
/// `alter://KEY[/path/to/file]` → yerel block store'dan dosya servis eder.
///
/// Manifesto VI: "Tarayıcıyı aç, adresi yaz, içeriği gör."
pub fn handle_alter_protocol<R: tauri::Runtime>(
    _ctx: tauri::UriSchemeContext<'_, R>,
    request: tauri::http::Request<Vec<u8>>,
) -> tauri::http::Response<Vec<u8>> {
    let uri = request.uri().to_string();

    // URI'den key ve path ayrıştır: alter://KEY[/subpath]
    let without_scheme = uri.strip_prefix("alter://").unwrap_or(&uri);
    let (key_part, file_path) = if let Some(idx) = without_scheme.find('/') {
        (&without_scheme[..idx], &without_scheme[idx..])
    } else {
        (without_scheme, "/index.html")
    };

    let alter_uri = format!("alter://{}", key_part);

    // Pubkey çöz
    let pubkey_bytes = match alter_uri_to_pubkey(&alter_uri) {
        Ok(b) => b,
        Err(_) => {
            return error_response(400, "Geçersiz alter:// adresi");
        }
    };
    let pubkey_hex = pubkey_to_hex(&pubkey_bytes);

    // Blok store veri dizini
    let data_dir = dirs_data_dir();
    let extracted_dir = data_dir.join("extracted").join(&pubkey_hex);

    // İstenen dosya mevcut mu?
    let file = extracted_dir.join(file_path.trim_start_matches('/'));
    if file.exists() {
        match std::fs::read(&file) {
            Ok(data) => {
                let mime = mime_from_path(&file);
                return tauri::http::Response::builder()
                    .status(200)
                    .header("Content-Type", mime)
                    .header("Access-Control-Allow-Origin", "*")
                    .body(data)
                    .unwrap_or_else(|_| error_response(500, "Yanıt oluşturulamadı"));
            }
            Err(e) => return error_response(500, &format!("Dosya okunamadı: {e}")),
        }
    }

    // İçerik mevcut değil → yükleme sayfası döndür
    // JS fetch komutu aracılığıyla arka planda çekme başlatır
    let loading_html = loading_page(&alter_uri);
    tauri::http::Response::builder()
        .status(200)
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Access-Control-Allow-Origin", "*")
        .body(loading_html.into_bytes())
        .unwrap_or_else(|_| error_response(500, "Yükleme sayfası oluşturulamadı"))
}

// ═══════════════════════════════════════════════
// IPC Komutları
// ═══════════════════════════════════════════════

#[derive(Serialize)]
pub struct FetchResult {
    pub status: String,
    pub alter_uri: String,
    pub path: Option<String>,
    pub error: Option<String>,
}

/// Bir alter:// adresinden içerik çek (arkaplanda).
///
/// Manifesto III: manifest imzası ve her blok hash'i doğrulanır.
#[tauri::command]
pub async fn fetch_site(
    uri: String,
    app: AppHandle,
    state: State<'_, BrowserState>,
) -> Result<FetchResult, String> {
    // Önce node başlat (gerekiyorsa)
    ensure_node_running(&state).await?;

    let pubkey_bytes =
        alter_uri_to_pubkey(&uri).map_err(|e| format!("Geçersiz URI: {e}"))?;
    let pubkey_hex = pubkey_to_hex(&pubkey_bytes);

    // Durumu "çekiliyor" olarak işaretle
    {
        let mut inner = state.inner.lock().unwrap();
        inner.fetch_status.insert(pubkey_hex.clone(), FetchStatus::Fetching { progress: 0 });
    }

    // Arkaplanda çekme başlat
    let uri_clone = uri.clone();
    let pubkey_hex_clone = pubkey_hex.clone();
    let app_clone = app.clone();

    tokio::spawn(async move {
        match do_fetch_site(&uri_clone, &pubkey_hex_clone).await {
            Ok(path) => {
                // Durumu güncelle — fetch tamamlandı
                if let Some(state) = app_clone.try_state::<BrowserState>() {
                    let mut inner = state.inner.lock().unwrap();
                    inner.fetch_status.insert(
                        pubkey_hex_clone.clone(),
                        FetchStatus::Ready { path: path.to_string_lossy().to_string() },
                    );
                }
                // Frontend'e "site hazır" eventi gönder
                let _ = app_clone.emit("site-ready", &uri_clone);
            }
            Err(e) => {
                tracing::error!("Fetch hatası ({}): {}", uri_clone, e);
                if let Some(state) = app_clone.try_state::<BrowserState>() {
                    let mut inner = state.inner.lock().unwrap();
                    inner.fetch_status.insert(
                        pubkey_hex_clone,
                        FetchStatus::Error { message: e.to_string() },
                    );
                }
                let _ = app_clone.emit("site-error", &uri_clone);
            }
        }
    });

    Ok(FetchResult {
        status: "fetching".into(),
        alter_uri: uri,
        path: None,
        error: None,
    })
}

/// Site çekme durumunu sorgula.
#[tauri::command]
pub fn get_site_status(uri: String, state: State<'_, BrowserState>) -> FetchStatus {
    let pubkey_bytes = alter_uri_to_pubkey(&uri).unwrap_or_default();
    let pubkey_hex = pubkey_to_hex(&pubkey_bytes);
    let inner = state.inner.lock().unwrap();
    inner
        .fetch_status
        .get(&pubkey_hex)
        .cloned()
        .unwrap_or(FetchStatus::Idle)
}

/// İsim çözümle: petname veya alter:// URI → tam alter:// URI döndür.
#[tauri::command]
pub fn resolve_name(name: String, state: State<'_, BrowserState>) -> Result<String, String> {
    let inner = state.inner.lock().unwrap();
    let data_dir = inner.config.data_dir.clone();
    drop(inner);

    // Zaten alter:// URI ise doğrula ve döndür
    if name.starts_with("alter://") {
        alter_uri_to_pubkey(&name).map_err(|e| format!("Geçersiz alter:// URI: {e}"))?;
        return Ok(name);
    }

    // Petname deposundan çöz (senkron yükleme)
    let petname_path = data_dir.join("petnames.cbor");
    if petname_path.exists()
        && let Ok(bytes) = std::fs::read(&petname_path)
        && let Ok(entries) = ciborium::from_reader::<Vec<alternet_core::naming::PetnameEntry>, _>(
            bytes.as_slice(),
        )
    {
        for entry in &entries {
            if entry.name == name
                && let Ok(pubkey) =
                    data_encoding::HEXLOWER.decode(entry.pubkey_hex.as_bytes())
            {
                return Ok(pubkey_to_alter_uri(&pubkey));
            }
        }
    }

    Err(format!("Bilinmeyen isim: '{name}' — alter:// URI veya kayıtlı petname kullanın"))
}

// ═══════════════════════════════════════════════
// Dahili Yardımcılar
// ═══════════════════════════════════════════════

async fn do_fetch_site(uri: &str, pubkey_hex: &str) -> anyhow::Result<PathBuf> {
    // pubkey_bytes URI parse doğrulaması için kullanılıyor (yalnızca başarı/başarısızlık önemli)
    alter_uri_to_pubkey(uri).map_err(|e| anyhow::anyhow!("URI hatası: {e}"))?;

    let data_dir = dirs_data_dir();
    let config = AlterNetConfig {
        data_dir: data_dir.clone(),
        mdns_enabled: true,
        ..Default::default()
    };

    let keypair = load_or_generate_keypair(config.keyfile_path())
        .map_err(|e| anyhow::anyhow!("Keypair: {e}"))?;

    let store = Arc::new(
        FsBlockStore::new(data_dir.join("blocks"), 0)
            .await
            .map_err(|e| anyhow::anyhow!("Store: {e}"))?,
    );

    let node = spawn_node(keypair, config, Arc::clone(&store))
        .await
        .map_err(|e| anyhow::anyhow!("Node: {e}"))?;

    node.listen_on(0)
        .await
        .map_err(|e| anyhow::anyhow!("Listen: {e}"))?;

    // DHT bootstrap bekle
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Manifest al + doğrula
    let manifest_bytes = tokio::time::timeout(
        Duration::from_secs(60),
        node.get_manifest(pubkey_hex),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Manifest zaman aşımı"))?
    .map_err(|e| anyhow::anyhow!("Manifest alınamadı: {e}"))?;

    let manifest =
        deserialize_manifest(&manifest_bytes).map_err(|e| anyhow::anyhow!("Parse: {e}"))?;
    verify_manifest(&manifest).map_err(|e| anyhow::anyhow!("İmza: {e}"))?;

    // Blokları BFS indir
    let mut queue = VecDeque::new();
    queue.push_back(manifest.root_cid.clone());

    while let Some(cid) = queue.pop_front() {
        if store.has(&cid).await.unwrap_or(false) {
            if let Ok(Some(data)) = store.get(&cid).await
                && let Ok(dag_node) = cbor_decode::<DagNode>(&data) {
                match dag_node {
                    DagNode::Internal { links, .. } => queue.extend(links),
                    DagNode::Directory { entries } => {
                        queue.extend(entries.into_iter().map(|e| e.cid))
                    }
                    _ => {}
                }
            }
            continue;
        }

        let providers = tokio::time::timeout(
            Duration::from_secs(30),
            node.get_providers(&cid),
        )
        .await
        .unwrap_or(Ok(vec![]))
        .unwrap_or_default();

        let mut fetched = false;
        for peer in providers {
            if let Ok(data) = tokio::time::timeout(
                Duration::from_secs(30),
                node.request_block(peer, &cid),
            )
            .await
            .unwrap_or(Err(alternet_core::error::AlterNetError::Network("timeout".into())))
            {
                store.put(&data).await.ok();
                if let Ok(dag_node) = cbor_decode::<DagNode>(&data) {
                    match dag_node {
                        DagNode::Internal { links, .. } => queue.extend(links),
                        DagNode::Directory { entries } => {
                            queue.extend(entries.into_iter().map(|e| e.cid))
                        }
                        _ => {}
                    }
                }
                fetched = true;
                break;
            }
        }
        if !fetched {
            tracing::warn!("Blok indirilemedi: {}", cid);
        }
    }

    // İçeriği dosya sistemine çıkar
    let extracted_dir = data_dir.join("extracted").join(pubkey_hex);
    tokio::fs::create_dir_all(&extracted_dir).await?;
    extract_dag(&*store, &manifest.root_cid, &extracted_dir)
        .await
        .map_err(|e| anyhow::anyhow!("Extract: {e}"))?;

    Ok(extracted_dir)
}

async fn ensure_node_running(state: &State<'_, BrowserState>) -> Result<(), String> {
    let needs_init = {
        let inner = state.inner.lock().unwrap();
        inner.node.is_none()
    };

    if needs_init {
        let data_dir = {
            let inner = state.inner.lock().unwrap();
            inner.config.data_dir.clone()
        };

        let config = AlterNetConfig {
            data_dir: data_dir.clone(),
            mdns_enabled: true,
            ..Default::default()
        };

        let keypair = load_or_generate_keypair(config.keyfile_path())
            .map_err(|e| format!("Keypair: {e}"))?;

        let store = Arc::new(
            FsBlockStore::new(data_dir.join("blocks"), 0)
                .await
                .map_err(|e| format!("Store: {e}"))?,
        );

        let node = spawn_node(keypair, config, Arc::clone(&store))
            .await
            .map_err(|e| format!("Node: {e}"))?;

        node.listen_on(0).await.map_err(|e| format!("Listen: {e}"))?;

        let mut inner = state.inner.lock().unwrap();
        inner.node = Some(Arc::new(node));
        inner.store = Some(store);
    }

    Ok(())
}

fn dirs_data_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".alternet")
    } else {
        PathBuf::from(".alternet")
    }
}

fn mime_from_path(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css",
        Some("js") | Some("mjs") => "application/javascript",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("wasm") => "application/wasm",
        Some("ico") => "image/x-icon",
        Some("txt") => "text/plain; charset=utf-8",
        Some("md") => "text/markdown; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn error_response(status: u16, msg: &str) -> tauri::http::Response<Vec<u8>> {
    let body = format!(
        r#"<!DOCTYPE html><html><body style="font-family:monospace;padding:2rem">
        <h2>⚠ AlterNet Hatası</h2><p>{msg}</p></body></html>"#
    );
    tauri::http::Response::builder()
        .status(status)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(body.into_bytes())
        .unwrap()
}

fn loading_page(uri: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <title>AlterNet — Yükleniyor</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
      min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
      background: linear-gradient(135deg, #0a0a1a 0%, #1a0a2e 50%, #0a1a2e 100%);
      color: #e0e0ff;
      font-family: 'Segoe UI', system-ui, sans-serif;
    }}
    .card {{
      background: rgba(255,255,255,0.05);
      backdrop-filter: blur(20px);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 16px;
      padding: 3rem;
      text-align: center;
      max-width: 480px;
    }}
    .spinner {{
      width: 48px; height: 48px;
      border: 3px solid rgba(120,80,255,0.3);
      border-top-color: #7850ff;
      border-radius: 50%;
      animation: spin 1s linear infinite;
      margin: 0 auto 1.5rem;
    }}
    @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
    h2 {{ font-size: 1.4rem; margin-bottom: 0.5rem; color: #c0b0ff; }}
    .uri {{ font-size: 0.8rem; color: #8080a0; word-break: break-all; margin: 1rem 0; }}
    .status {{ font-size: 0.9rem; color: #a090c0; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="spinner"></div>
    <h2>İçerik Yükleniyor</h2>
    <div class="uri">{uri}</div>
    <p class="status" id="status">P2P ağından içerik çekiliyor...</p>
  </div>
  <script>
    const uri = "{uri}";
    let attempts = 0;
    function checkReady() {{
      attempts++;
      if (attempts > 120) {{
        document.getElementById('status').textContent = 'Zaman aşımı — lütfen tekrar deneyin.';
        return;
      }}
      window.__TAURI__?.core?.invoke('get_site_status', {{ uri }})
        .then(status => {{
          if (status.Ready) {{
            document.getElementById('status').textContent = 'Hazır! Yönlendiriliyor...';
            setTimeout(() => location.reload(), 300);
          }} else if (status.Error) {{
            document.getElementById('status').textContent = 'Hata: ' + status.Error.message;
          }} else {{
            document.getElementById('status').textContent =
              'İndiriliyor... (' + attempts + ')';
            setTimeout(checkReady, 1500);
          }}
        }})
        .catch(() => setTimeout(checkReady, 2000));
    }}
    // Fetch başlat ve durumu kontrol et
    window.__TAURI__?.core?.invoke('fetch_site', {{ uri }})
      .then(() => setTimeout(checkReady, 1000))
      .catch(() => setTimeout(checkReady, 2000));
  </script>
</body>
</html>"#
    )
}

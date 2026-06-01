//! # AlterNet Node — Headless Seed/Relay Daemon
//!
//! Ağa gönüllü olarak hizmet veren daemon. İçerik barındırır, blok değişimine katılır,
//! provider kayıtlarını yeniler ve yapılandırılmış siteleri otomatik seed eder.
//!
//! **Manifesto II:** Her cihaz hem istemci hem sunucu olabilir.
//! Bu daemon gönüllük esasına göre çalışır — kimse zorlamaz.
//!
//! ## Kullanım
//! ```bash
//! # Varsayılan ayarlarla başlat
//! alternet-node
//!
//! # TOML yapılandırma ile
//! alternet-node --config /etc/alternet/node.toml
//!
//! # Komut satırı ayarları (TOML'u ezer)
//! alternet-node --port 4001 --storage-quota 10G --pin alter://abc123
//! ```

use alternet_core::{
    config::AlterNetConfig,
    content::{BlockStore as _, FsBlockStore},
    identity::{alter_uri_to_pubkey, load_identity, pubkey_to_alter_uri, pubkey_to_hex},
    libp2p,
    network::spawn_node,
    publish::{deserialize_manifest, serialize_manifest, verify_manifest},
    replication::{PinStore, Replicator},
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc, time::Duration};

// ═══════════════════════════════════════════════
// TOML Yapılandırması
// ═══════════════════════════════════════════════

/// TOML dosyasından yüklenen node yapılandırması.
///
/// Örnek `node.toml`:
/// ```toml
/// port = 4001
/// storage_quota = "10G"
/// relay_enabled = true
/// refresh_interval_secs = 3600
///
/// [[pin]]
/// uri = "alter://abc123..."
/// label = "Haberler sitesi"
/// ```
#[derive(Debug, Serialize, Deserialize, Default)]
struct NodeConfig {
    port: Option<u16>,
    data_dir: Option<PathBuf>,
    storage_quota: Option<String>,
    bootstrap_addrs: Option<Vec<String>>,
    relay_enabled: Option<bool>,
    /// Provider record TTL yenileme aralığı (saniye, varsayılan: 3600)
    refresh_interval_secs: Option<u64>,
    /// Otomatik seed edilecek siteler
    #[serde(default)]
    pin: Vec<PinConfigEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PinConfigEntry {
    uri: String,
    label: Option<String>,
}

impl NodeConfig {
    fn from_file(path: &PathBuf) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("TOML okunamadı {}: {e}", path.display()))?;
        toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("TOML ayrıştırma hatası: {e}"))
    }
}

// ═══════════════════════════════════════════════
// CLI
// ═══════════════════════════════════════════════

#[derive(Parser)]
#[command(
    name = "alternet-node",
    about = "AlterNet Headless Seed/Relay Daemon",
    version,
    long_about = "AlterNet ağına gönüllü olarak hizmet veren daemon.\n\
                  Blokları barındırır, relay sağlar, ağı güçlendirir.\n\
                  \n\
                  Manifesto II: Her cihaz hem istemci hem sunucudur."
)]
struct Cli {
    /// TOML yapılandırma dosyası yolu
    #[arg(long)]
    config: Option<PathBuf>,
    /// Dinleme portu (varsayılan: 4001)
    #[arg(long)]
    port: Option<u16>,
    /// Veri dizini (varsayılan: ~/.alternet)
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Depolama kotası (örn: 10G, 500M; varsayılan: adaptif)
    #[arg(long)]
    storage_quota: Option<String>,
    /// Bootstrap node adresleri
    #[arg(long)]
    bootstrap: Vec<String>,
    /// Seed/pin edilecek alter:// URI'leri
    #[arg(long = "pin")]
    pin_uris: Vec<String>,
    /// Kimlik şifreleme parolası (ALTERNET_PASSWORD env ile de verilebilir)
    #[arg(long)]
    password: Option<String>,
    /// Provider record yenileme aralığı (saniye, varsayılan: 3600)
    #[arg(long, default_value = "3600")]
    refresh_interval: u64,
}

// ═══════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("alternet=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    // TOML yükle (varsa), CLI argümanları üzerine yazar
    let file_cfg = cli
        .config
        .as_ref()
        .map(NodeConfig::from_file)
        .transpose()?
        .unwrap_or_default();

    // Yapılandırmayı birleştir (CLI > TOML > varsayılan)
    let port = cli.port.or(file_cfg.port).unwrap_or(4001);
    let refresh_secs =
        file_cfg.refresh_interval_secs.unwrap_or(cli.refresh_interval);

    let mut config = AlterNetConfig::default();
    if let Some(dir) = cli.data_dir.or(file_cfg.data_dir) {
        config.data_dir = dir;
    }
    config.dht_server_mode = true;
    config.relay_enabled = file_cfg.relay_enabled.unwrap_or(true);

    let mut bootstrap = cli.bootstrap;
    if let Some(mut addrs) = file_cfg.bootstrap_addrs {
        bootstrap.append(&mut addrs);
    }
    config.bootstrap_addrs = bootstrap;

    let quota_str = cli.storage_quota.or(file_cfg.storage_quota);
    if let Some(ref q) = quota_str {
        config.storage_quota = parse_quota(q)?;
    }

    // Pin listesi (CLI + TOML birleştir)
    let mut pin_entries: Vec<PinConfigEntry> = cli
        .pin_uris
        .into_iter()
        .map(|u| PinConfigEntry { uri: u, label: None })
        .collect();
    pin_entries.extend(file_cfg.pin);

    // Keypair yükle / oluştur (parola varsa şifreli — Manifesto III)
    let password = cli
        .password
        .or_else(|| std::env::var("ALTERNET_PASSWORD").ok())
        .filter(|p| !p.is_empty());
    if password.is_none() {
        tracing::warn!(
            "Kimlik düz (şifresiz) saklanıyor — şifrelemek için --password / ALTERNET_PASSWORD"
        );
    }
    let keypair = load_identity(config.keyfile_path(), password.as_deref())
        .map_err(|e| anyhow::anyhow!("Keypair yüklenemedi: {e}"))?;

    let peer_id = libp2p::PeerId::from(keypair.public());
    let pubkey_bytes = keypair.public().encode_protobuf();
    let uri = pubkey_to_alter_uri(&pubkey_bytes);

    println!("AlterNet Node başlatılıyor...");
    println!("  PeerID  : {}", peer_id);
    println!("  Adres   : {}", uri);
    println!("  Veri    : {}", config.data_dir.display());
    println!("  Relay   : {}", config.relay_enabled);
    println!("  Yenileme: {}s", refresh_secs);
    if !pin_entries.is_empty() {
        println!("  Pin     : {} site", pin_entries.len());
    }

    let blocks_dir = config.blocks_dir();
    let quota = config.effective_storage_quota();
    let store = Arc::new(
        FsBlockStore::new(blocks_dir, quota)
            .await
            .map_err(|e| anyhow::anyhow!("Block store başlatılamadı: {e}"))?,
    );

    // PinStore aç
    let pin_store = PinStore::open(&config.data_dir).await.unwrap_or_else(|e| {
        tracing::warn!("PinStore açılamadı: {e}, bellekte devam ediliyor");
        PinStore::in_memory()
    });

    let mut replicator = Replicator::new(Arc::clone(&store), pin_store, quota);

    // Node başlat
    let node = spawn_node(keypair, config.clone(), Arc::clone(&store))
        .await
        .map_err(|e| anyhow::anyhow!("Node başlatılamadı: {e}"))?;

    let listen_addr = node
        .listen_on(port)
        .await
        .map_err(|e| anyhow::anyhow!("Dinleme başlatılamadı: {e}"))?;

    println!("Dinleniyor: {}/p2p/{}", listen_addr, peer_id);

    // DHT bootstrap için bekle
    if !pin_entries.is_empty() || !config.bootstrap_addrs.is_empty() {
        tracing::info!("DHT bootstrap bekleniyor (5s)...");
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    // Yapılandırılmış siteleri pin'le / seed et
    for entry in &pin_entries {
        if let Err(e) = seed_site(&node, &store, &mut replicator, entry).await {
            tracing::warn!("Site seed edilemedi ({}): {e}", entry.uri);
        }
    }

    // PinStore'daki mevcut blokları sağlayıcı olarak duyur
    announce_pinned_blocks(&node, &replicator).await;

    println!("Hazır. Ctrl+C ile durdurun.");

    // Periyodik yenileme döngüsü
    let refresh_interval = Duration::from_secs(refresh_secs);
    let node_for_refresh = node;
    let store_for_refresh = Arc::clone(&store);

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("\nDurduruluyor...");
        }
        _ = refresh_loop(node_for_refresh, store_for_refresh, replicator, refresh_interval) => {
            // Normalde buraya gelmez (sonsuz döngü)
        }
    }

    Ok(())
}

// ═══════════════════════════════════════════════
// Site Seeding
// ═══════════════════════════════════════════════

async fn seed_site(
    node: &alternet_core::network::NodeHandle,
    store: &FsBlockStore,
    replicator: &mut Replicator,
    entry: &PinConfigEntry,
) -> anyhow::Result<()> {
    let pubkey_bytes = alter_uri_to_pubkey(&entry.uri)
        .map_err(|e| anyhow::anyhow!("Geçersiz URI: {e}"))?;
    let pubkey_hex = pubkey_to_hex(&pubkey_bytes);

    tracing::info!("Site seed ediliyor: {}", entry.uri);

    // Manifest'i DHT'den al
    let manifest_bytes = tokio::time::timeout(
        Duration::from_secs(60),
        node.get_manifest(&pubkey_hex),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Manifest alma zaman aşımı"))?
    .map_err(|e| anyhow::anyhow!("Manifest alınamadı: {e}"))?;

    let manifest = deserialize_manifest(&manifest_bytes)
        .map_err(|e| anyhow::anyhow!("Manifest ayrıştırılamadı: {e}"))?;
    verify_manifest(&manifest)
        .map_err(|e| anyhow::anyhow!("Manifest imza hatası: {e}"))?;

    tracing::info!(
        "Manifest doğrulandı (seq={}, root={})",
        manifest.sequence,
        manifest.root_cid
    );

    // Blokları indir (BFS)
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(manifest.root_cid.clone());
    let mut all_cids = Vec::new();

    while let Some(cid) = queue.pop_front() {
        if store.has(&cid).await.unwrap_or(false) {
            all_cids.push(cid.clone());
            // Çocukları da kuyruğa ekle
            if let Ok(Some(data)) = store.get(&cid).await
                && let Ok(node_data) =
                    alternet_core::content::cbor_decode::<alternet_core::types::DagNode>(&data)
            {
                match node_data {
                    alternet_core::types::DagNode::Internal { links, .. } => {
                        queue.extend(links);
                    }
                    alternet_core::types::DagNode::Directory { entries } => {
                        queue.extend(entries.into_iter().map(|e| e.cid));
                    }
                    _ => {}
                }
            }
            continue;
        }

        // Provider bul ve bloğu al
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
                all_cids.push(cid.clone());
                // Çocukları kuyruğa ekle
                if let Ok(node_data) =
                    alternet_core::content::cbor_decode::<alternet_core::types::DagNode>(&data)
                {
                    match node_data {
                        alternet_core::types::DagNode::Internal { links, .. } => {
                            queue.extend(links);
                        }
                        alternet_core::types::DagNode::Directory { entries } => {
                            queue.extend(entries.into_iter().map(|e| e.cid));
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

    tracing::info!("Seed tamamlandı: {} blok", all_cids.len());

    // Pin kaydını güncelle
    replicator.pin(
        manifest.root_cid.clone(),
        pubkey_hex,
        all_cids.clone(),
        entry.label.clone(),
    );

    // Provider olarak duyur
    for cid in &all_cids {
        node.start_providing(cid).await.ok();
    }

    // Manifest'i de yeniden yayınla
    node.put_manifest(
        &pubkey_to_hex(&pubkey_bytes),
        serialize_manifest(&manifest).unwrap_or_default(),
    )
    .await
    .ok();

    Ok(())
}

async fn announce_pinned_blocks(
    node: &alternet_core::network::NodeHandle,
    replicator: &Replicator,
) {
    let cids = replicator.pins.all_pinned_cids();
    if cids.is_empty() {
        return;
    }
    tracing::info!("Pinlenmiş {} blok duyuruluyor...", cids.len());
    for cid in cids {
        node.start_providing(&cid).await.ok();
    }
}

// ═══════════════════════════════════════════════
// Periyodik Yenileme Döngüsü
// ═══════════════════════════════════════════════

/// Provider kayıtlarını DHT TTL'inden önce yenile.
///
/// Kademlia provider kayıtları varsayılan 24h TTL ile sona erer.
/// Bu döngü periyodik olarak `start_providing` tekrar çağırarak
/// kaydın canlı kalmasını sağlar.
async fn refresh_loop(
    node: alternet_core::network::NodeHandle,
    store: Arc<FsBlockStore>,
    replicator: Replicator,
    interval: Duration,
) {
    loop {
        tokio::time::sleep(interval).await;
        tracing::info!("Provider kayıtları yenileniyor...");

        let cids = replicator.pins.all_pinned_cids();
        for cid in &cids {
            if store.has(cid).await.unwrap_or(false) {
                node.start_providing(cid).await.ok();
            }
        }

        // GC: disk kotası aşıldıysa temizle
        let used = store.total_size().await.unwrap_or(0);
        let quota = replicator.quota;
        if quota > 0 && used > quota {
            tracing::warn!(
                "Disk kotası aşıldı: kullanılan={} kota={} — GC çalıştırılıyor",
                used,
                quota
            );
            if let Ok(report) = replicator.gc(false).await {
                tracing::info!(
                    "GC tamamlandı: {} blok silindi, {} byte serbest",
                    report.deleted_blocks,
                    report.freed_bytes
                );
            }
        }

        tracing::info!("Yenileme tamamlandı ({} blok)", cids.len());
    }
}

// ═══════════════════════════════════════════════
// Yardımcı
// ═══════════════════════════════════════════════

fn parse_quota(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    let (num_str, mult) = if let Some(n) = s.strip_suffix('G').or_else(|| s.strip_suffix('g')) {
        (n, 1024 * 1024 * 1024u64)
    } else if let Some(n) = s.strip_suffix('M').or_else(|| s.strip_suffix('m')) {
        (n, 1024 * 1024u64)
    } else if let Some(n) = s.strip_suffix('K').or_else(|| s.strip_suffix('k')) {
        (n, 1024u64)
    } else {
        (s, 1u64)
    };
    let n: u64 = num_str.parse().map_err(|_| anyhow::anyhow!("Geçersiz kota: {}", s))?;
    Ok(n * mult)
}

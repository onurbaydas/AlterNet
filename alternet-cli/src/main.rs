//! # AlterNet CLI
//!
//! Sunucusuz, hesapsız içerik yayınlama ve erişim aracı.
//!
//! **Manifesto I:** Hiçbir sunucu, şirket veya devlet otorite sahibi değildir.
//! **Manifesto VI:** Basit kullanım — `publish ./mysite` → `alter://...` adres döner.

use alternet_core::{
    apps::{AppHost, AppManifest, Capability, create_app_manifest},
    board::CrdtBoard,
    config::AlterNetConfig,
    content::{
        BlockStore as _, FsBlockStore, build_dag_keyed, collect_all_cids, extract_dag_keyed,
    },
    discovery::{TagClaim, create_tag_claim, tag_dht_key, verify_tag_claim},
    governance::create_zone_delegation,
    identity::{alter_uri_to_pubkey, load_identity, pubkey_to_alter_uri, pubkey_to_hex},
    libp2p,
    naming::{
        NameResolver as _, PetnameStore, ZoneStore, petnames_dht_key, resolve_full_uri,
        sign_petname_list, zone_dht_key,
    },
    network::spawn_node,
    publish::{create_manifest, deserialize_manifest, serialize_manifest, verify_manifest},
    routing::PrivacyLevel,
    types::ManifestMeta,
};
use clap::Parser;
use std::{path::PathBuf, sync::Arc, time::Duration};

// ═══════════════════════════════════════════════
// CLI Yapısı
// ═══════════════════════════════════════════════

#[derive(Parser)]
#[command(
    name = "alternet-cli",
    about = "AlterNet — Alternatif İnternet CLI",
    version,
    long_about = "Sunucusuz, hesapsız, sansüre dayanıklı içerik yayınlama ve erişim.\n\
                  \n\
                  Örnek:\n\
                  alternet-cli publish ./mysite    → alter://... adres döner\n\
                  alternet-cli fetch alter://...   → içerik indirilir\n\
                  alternet-cli pin alter://...     → site yeniden barındırılır"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Veri dizini (varsayılan: ~/.alternet)
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    /// Gizlilik seviyesi: clear | padded (varsayılan) | onion | tor
    ///
    /// padded: 512B padding + chaff + time-blind (trafik analizi engeli)
    /// onion:  Sphinx 3-hop onion routing (gönderen kimliği gizli)
    /// tor:    Tor network üzerinden (IP tamamen gizli, `tor` daemon gerektirir)
    #[arg(long, global = true, default_value = "padded")]
    privacy: String,

    /// Tor transport etkinleştir (--privacy tor ile aynı etki)
    #[arg(long, global = true)]
    tor: bool,

    /// Kimlik şifreleme parolası (Argon2+AES). Verilmezse anahtar düz saklanır (uyarılır).
    /// ALTERNET_PASSWORD ortam değişkeniyle de verilebilir. Manifesto III: atıl veri şifreli.
    #[arg(long, global = true)]
    password: Option<String>,

    /// Bağlanılacak bilinen peer adresi (multiaddr/p2p/PeerId). Tekrarlanabilir.
    /// Manifesto I: otorite değil — kullanıcının seçtiği opsiyonel giriş noktası.
    #[arg(long = "peer", global = true)]
    peers: Vec<String>,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Ed25519 kimlik oluştur veya mevcut kimliği göster
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
    /// Bir dizini AlterNet'e yayınla
    Publish {
        /// Yayınlanacak dizin veya dosya yolu
        path: String,
        /// Anahtar dosyası yolu
        #[arg(long)]
        keyfile: Option<String>,
        /// Dinleme portu (0 = rastgele)
        #[arg(long, default_value = "0")]
        port: u16,
        /// Site başlığı
        #[arg(long)]
        title: Option<String>,
        /// Açıklama
        #[arg(long)]
        description: Option<String>,
        /// Keşif etiketi (birden fazla için tekrarlayın: --tag blog --tag haber)
        #[arg(long = "tag")]
        tags: Vec<String>,
        /// İçerik şifreleme parolası (opsiyonel — içerik anahtarsız okunamaz, Manifesto III)
        #[arg(long)]
        encrypt_key: Option<String>,
    },
    /// Bir alter:// adresinden içerik indir
    Fetch {
        /// alter:// URI (örn: alter://abc123...)
        uri: String,
        /// Şifreli içerik için çözme parolası (--encrypt-key ile aynı olmalı)
        #[arg(long)]
        decrypt_key: Option<String>,
        /// Çıktı dizini
        #[arg(long, default_value = "./fetched")]
        output: String,
        /// Dinleme portu
        #[arg(long, default_value = "0")]
        port: u16,
        /// Keşif bekleme süresi (saniye)
        #[arg(long, default_value = "5")]
        wait_secs: u64,
    },
    /// Bir siteyi pin'le (yeniden barındır, seed)
    Pin {
        /// alter:// URI
        uri: String,
        /// Dinleme portu
        #[arg(long, default_value = "0")]
        port: u16,
        /// Keşif bekleme süresi (saniye)
        #[arg(long, default_value = "5")]
        wait_secs: u64,
    },
    /// Yerel isim (petname) ve zone delegasyonu yönetimi (AlterNS / Madde IV)
    Name {
        #[command(subcommand)]
        action: NameAction,
    },
    /// Etikete göre içerik ara (Faz 5 — discovery)
    Search {
        /// Etiket (ör. "blog", "haber")
        tag: String,
        #[arg(long, default_value = "0")]
        port: u16,
        #[arg(long, default_value = "5")]
        wait_secs: u64,
    },
    /// Bir WASM uygulamasını capability sandbox içinde çalıştır (Faz 5 — AlterApps)
    App {
        #[command(subcommand)]
        action: AppAction,
    },
    /// WoT akışı: güvendiğin yazarlara abone ol, güncellemelerini topla (Faz 5)
    Feed {
        #[command(subcommand)]
        action: FeedAction,
    },
    /// CRDT board (forum/wiki) — merkeziz ortak durum (Faz 5)
    Board {
        #[command(subcommand)]
        action: BoardAction,
    },
}

#[derive(clap::Subcommand)]
enum FeedAction {
    /// Bir yazara abone ol: feed subscribe alter://KEY
    Subscribe { uri: String },
    /// Abonelikten çık
    Unsubscribe { uri: String },
    /// Abonelikleri listele
    List,
    /// Abone olunan yazarların en güncel manifestlerini DHT'den topla
    Pull {
        #[arg(long, default_value = "0")]
        port: u16,
        #[arg(long, default_value = "5")]
        wait_secs: u64,
    },
}

#[derive(clap::Subcommand)]
enum BoardAction {
    /// Board'a girdi ekle ve DHT'ye yayınla: board post <board-id> <baslik> <govde>
    Post {
        board_id: String,
        title: String,
        body: String,
        #[arg(long, default_value = "0")]
        port: u16,
        #[arg(long, default_value = "5")]
        wait_secs: u64,
    },
    /// Board'u DHT'den oku (yerel ile merge ederek tüm girdileri göster)
    Read {
        board_id: String,
        #[arg(long, default_value = "0")]
        port: u16,
        #[arg(long, default_value = "5")]
        wait_secs: u64,
    },
}

#[derive(clap::Subcommand)]
enum NameAction {
    /// Yerel petname ata: name set alice alter://KEY
    Set { petname: String, uri: String },
    /// Yerel petname'leri listele
    List,
    /// Petname sil
    Rm { petname: String },
    /// İsmi çöz (yerel petname / self-cert / DHT zone)
    Resolve {
        name: String,
        #[arg(long, default_value = "0")]
        port: u16,
        #[arg(long, default_value = "5")]
        wait_secs: u64,
    },
    /// Alt-isim delegasyonu yayınla: name delegate blog alter://CHILD (DHT'ye imzalı)
    Delegate {
        subname: String,
        child_uri: String,
        #[arg(long, default_value = "0")]
        port: u16,
        #[arg(long, default_value = "5")]
        wait_secs: u64,
    },
    /// Yerel petname listeni DHT'ye imzalı yayınla (başkaları WoT'ta kullanabilir)
    Publish {
        #[arg(long, default_value = "0")]
        port: u16,
        #[arg(long, default_value = "5")]
        wait_secs: u64,
    },
}

#[derive(clap::Subcommand)]
enum AppAction {
    /// İmzalı bir WASM uygulamasını çalıştır
    Run {
        /// WASM dosyası (.wasm)
        wasm: String,
        /// Manifest dosyası (.cbor) — imzalı AppManifest
        #[arg(long)]
        manifest: String,
        /// Giriş fonksiyonuna geçilecek i32 değer
        #[arg(long, default_value = "0")]
        input: i32,
        /// Yakıt limiti (sonsuz döngü koruması)
        #[arg(long, default_value = "10000000")]
        fuel: u64,
        /// Verilen capability'ler (clock, content-read, storage-write, network)
        #[arg(long = "cap")]
        caps: Vec<String>,
    },
    /// Bir WASM uygulaması için imzalı manifest oluştur
    Sign {
        wasm: String,
        #[arg(long)]
        entry: String,
        #[arg(long, default_value = "app")]
        id: String,
        #[arg(long)]
        output: String,
        #[arg(long = "cap")]
        caps: Vec<String>,
    },
}

#[derive(clap::Subcommand)]
enum IdentityAction {
    /// Yeni kimlik oluştur
    Generate {
        /// Çıktı dosyası
        #[arg(long)]
        output: Option<String>,
    },
    /// Mevcut kimliği göster
    Show {
        /// Anahtar dosyası
        #[arg(long)]
        keyfile: Option<String>,
    },
    /// Kimliği taşınabilir bir yedek dosyasına aktar (base32 metin)
    ///
    /// Manifesto I: Anahtar kaybı geri alınamaz, merkezi sıfırlama yoktur.
    /// Yedeği güvenli bir yerde sakla — bu dosya kimliğinin TAMAMIDIR.
    Backup {
        /// Yedek çıktı dosyası
        #[arg(long)]
        output: String,
        /// Kaynak anahtar dosyası
        #[arg(long)]
        keyfile: Option<String>,
    },
    /// Bir yedekten kimliği geri yükle
    Restore {
        /// Yedek dosyası (base32 metin)
        #[arg(long)]
        input: String,
        /// Hedef anahtar dosyası (varsayılan: ~/.alternet/identity.key)
        #[arg(long)]
        keyfile: Option<String>,
    },
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

    let mut config = AlterNetConfig::default();
    if let Some(dir) = cli.data_dir {
        config.data_dir = dir;
    }

    // Gizlilik seviyesi uygula — Manifesto III: güvenlik varsayılandır
    config.privacy_level = parse_privacy_level(&cli.privacy);
    if cli.tor {
        config.privacy_level = PrivacyLevel::Tor;
        config.tor_enabled = true;
    }

    // Kullanıcının belirttiği peer'lar bootstrap listesine eklenir (Madde I: opsiyonel).
    config.bootstrap_addrs.extend(cli.peers);

    // Parola: --password > ALTERNET_PASSWORD env. Yoksa düz depolama (uyarılır).
    let password = cli
        .password
        .or_else(|| std::env::var("ALTERNET_PASSWORD").ok())
        .filter(|p| !p.is_empty());

    match cli.command {
        Commands::Identity { action } => run_identity(action, &config, password.as_deref()).await,
        Commands::Publish { path, keyfile, port, title, description, tags, encrypt_key } => {
            run_publish(
                path, keyfile, port, title, description, tags, encrypt_key,
                password.as_deref(), config,
            )
            .await
        }
        Commands::Fetch { uri, decrypt_key, output, port, wait_secs } => {
            run_fetch(uri, decrypt_key, output, port, wait_secs, config).await
        }
        Commands::Pin { uri, port, wait_secs } => run_pin(uri, port, wait_secs, config).await,
        Commands::Name { action } => run_name(action, password.as_deref(), config).await,
        Commands::Search { tag, port, wait_secs } => {
            run_search(tag, port, wait_secs, config).await
        }
        Commands::App { action } => run_app(action, password.as_deref(), config).await,
        Commands::Feed { action } => run_feed(action, config).await,
        Commands::Board { action } => run_board(action, password.as_deref(), config).await,
    }
}

/// Parola yoksa düz depolama uyarısı (Manifesto III: atıl veri şifreli olmalı).
fn warn_if_plaintext(password: Option<&str>) {
    if password.is_none() {
        eprintln!(
            "⚠  Kimlik düz (şifresiz) saklanıyor. Şifrelemek için --password veya \
             ALTERNET_PASSWORD kullanın (Manifesto III)."
        );
    }
}

// ═══════════════════════════════════════════════
// Identity
// ═══════════════════════════════════════════════

async fn run_identity(
    action: IdentityAction,
    config: &AlterNetConfig,
    password: Option<&str>,
) -> anyhow::Result<()> {
    match action {
        IdentityAction::Generate { output } => {
            let keyfile_path = output
                .map(PathBuf::from)
                .unwrap_or_else(|| config.keyfile_path());
            if keyfile_path.exists() {
                anyhow::bail!("Anahtar dosyası zaten mevcut: {}", keyfile_path.display());
            }
            warn_if_plaintext(password);
            let keypair = load_identity(&keyfile_path, password)
                .map_err(|e| anyhow::anyhow!("Keypair oluşturulamadı: {e}"))?;
            let pubkey_bytes = keypair.public().encode_protobuf();
            let uri = pubkey_to_alter_uri(&pubkey_bytes);
            println!("Yeni kimlik oluşturuldu:");
            println!("  Adres: {}", uri);
            println!("  Dosya: {}", keyfile_path.display());
        }
        IdentityAction::Show { keyfile } => {
            let keyfile_path = keyfile
                .map(PathBuf::from)
                .unwrap_or_else(|| config.keyfile_path());
            let keypair = load_identity(&keyfile_path, password)
                .map_err(|e| anyhow::anyhow!("Keypair yüklenemedi: {e}"))?;
            let pubkey_bytes = keypair.public().encode_protobuf();
            let uri = pubkey_to_alter_uri(&pubkey_bytes);
            let peer_id = libp2p::PeerId::from(keypair.public());
            println!("Kimlik:");
            println!("  alter://  : {}", uri);
            println!("  PeerID    : {}", peer_id);
            println!("  Dosya     : {}", keyfile_path.display());
        }
        IdentityAction::Backup { output, keyfile } => {
            let keyfile_path = keyfile
                .map(PathBuf::from)
                .unwrap_or_else(|| config.keyfile_path());
            let keypair = load_identity(&keyfile_path, password)
                .map_err(|e| anyhow::anyhow!("Keypair yüklenemedi: {e}"))?;
            // Taşınabilir yedek: protobuf encoding → base32 metin
            let raw = keypair
                .to_protobuf_encoding()
                .map_err(|e| anyhow::anyhow!("Keypair encode edilemedi: {e:?}"))?;
            let encoded = data_encoding::BASE32_NOPAD.encode(&raw);
            std::fs::write(&output, &encoded)?;
            let uri = pubkey_to_alter_uri(&keypair.public().encode_protobuf());
            println!("Kimlik yedeklendi:");
            println!("  Adres : {}", uri);
            println!("  Yedek : {}", output);
            println!();
            println!("⚠  UYARI (Manifesto I): Bu dosya kimliğinin TAMAMIDIR.");
            println!("   Kaybedersen merkezi sıfırlama YOKTUR. Güvenli sakla, paylaşma.");
        }
        IdentityAction::Restore { input, keyfile } => {
            let keyfile_path = keyfile
                .map(PathBuf::from)
                .unwrap_or_else(|| config.keyfile_path());
            if keyfile_path.exists() {
                anyhow::bail!(
                    "Hedef anahtar dosyası zaten mevcut: {} (üzerine yazmamak için önce taşı/sil)",
                    keyfile_path.display()
                );
            }
            let encoded = std::fs::read_to_string(&input)?;
            let raw = data_encoding::BASE32_NOPAD
                .decode(encoded.trim().as_bytes())
                .map_err(|e| anyhow::anyhow!("Yedek base32 decode edilemedi: {e}"))?;
            // Doğrula: geçerli bir keypair mi?
            let keypair = libp2p::identity::Keypair::from_protobuf_encoding(&raw)
                .map_err(|e| anyhow::anyhow!("Geçersiz yedek (keypair çözülemedi): {e}"))?;
            if let Some(parent) = keyfile_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // Parola verildiyse şifreli, yoksa düz kaydet (Manifesto III).
            match password {
                Some(pw) => {
                    let enc = alternet_core::secure_storage::encrypt_file_data(pw, &raw);
                    std::fs::write(&keyfile_path, enc)?;
                }
                None => {
                    warn_if_plaintext(None);
                    std::fs::write(&keyfile_path, &raw)?;
                }
            }
            let uri = pubkey_to_alter_uri(&keypair.public().encode_protobuf());
            println!("Kimlik geri yüklendi:");
            println!("  Adres : {}", uri);
            println!("  Dosya : {}", keyfile_path.display());
        }
    }
    Ok(())
}

// ═══════════════════════════════════════════════
// Publish
// ═══════════════════════════════════════════════

#[allow(clippy::too_many_arguments)]
async fn run_publish(
    path: String,
    keyfile: Option<String>,
    port: u16,
    title: Option<String>,
    description: Option<String>,
    tags: Vec<String>,
    encrypt_key: Option<String>,
    password: Option<&str>,
    config: AlterNetConfig,
) -> anyhow::Result<()> {
    let path = PathBuf::from(&path);
    if !path.exists() {
        anyhow::bail!("Yol bulunamadı: {}", path.display());
    }

    // Keypair yükle
    let keyfile_path = keyfile.map(PathBuf::from).unwrap_or_else(|| config.keyfile_path());
    warn_if_plaintext(password);
    let keypair = load_identity(&keyfile_path, password)
        .map_err(|e| anyhow::anyhow!("Keypair yüklenemedi: {e}"))?;
    let pubkey_bytes = keypair.public().encode_protobuf();
    let pubkey_hex = pubkey_to_hex(&pubkey_bytes);
    let uri = pubkey_to_alter_uri(&pubkey_bytes);

    // Block store
    let blocks_dir = config.blocks_dir();
    let quota = config.effective_storage_quota();
    let store = Arc::new(
        FsBlockStore::new(blocks_dir, quota)
            .await
            .map_err(|e| anyhow::anyhow!("Block store başlatılamadı: {e}"))?,
    );

    // İçerik şifreleme anahtarı (opsiyonel — Manifesto III)
    let content_key = encrypt_key
        .as_deref()
        .map(alternet_core::crypto::derive_content_key);

    // DAG oluştur
    println!("DAG oluşturuluyor: {} ...", path.display());
    if content_key.is_some() {
        println!("  İçerik AES-256-GCM ile şifreleniyor (anahtarsız okunamaz)");
    }
    let root_cid = build_dag_keyed(&*store, &path, content_key)
        .await
        .map_err(|e| anyhow::anyhow!("DAG oluşturma başarısız: {e}"))?;

    let all_cids = collect_all_cids(&*store, &root_cid)
        .await
        .map_err(|e| anyhow::anyhow!("CID toplama başarısız: {e}"))?;

    println!("  Kök CID   : {}", root_cid);
    println!("  Blok sayısı: {}", all_cids.len());

    // Manifest oluştur (imzalı — Manifesto VII)
    let metadata = ManifestMeta {
        title,
        description,
        mime_type: Some("text/html".into()),
        tags: tags.clone(),
        encrypted: content_key.is_some(),
    };
    let manifest = create_manifest(root_cid, &keypair, 1, metadata)
        .map_err(|e| anyhow::anyhow!("Manifest oluşturma başarısız: {e}"))?;
    let manifest_bytes = serialize_manifest(&manifest)
        .map_err(|e| anyhow::anyhow!("Manifest seri hale getirme başarısız: {e}"))?;

    // Etiket beyanlarını keypair taşınmadan önce imzala (DHT'ye sonra yayınlanır).
    let tag_claims: Vec<(String, TagClaim)> = tags
        .iter()
        .filter_map(|t| {
            create_tag_claim(&keypair, t.clone(), pubkey_bytes.clone())
                .ok()
                .map(|c| (t.clone(), c))
        })
        .collect();

    let privacy_level_display = format!("{:?}", config.privacy_level);

    // Node başlat
    let node = spawn_node(keypair, config, Arc::clone(&store))
        .await
        .map_err(|e| anyhow::anyhow!("Node başlatılamadı: {e}"))?;
    let listen_addr = node
        .listen_on(port)
        .await
        .map_err(|e| anyhow::anyhow!("Dinleme başlatılamadı: {e}"))?;
    println!("Dinleniyor: {}/p2p/{}", listen_addr, node.local_peer_id());
    println!("Gizlilik  : {}", privacy_level_display);

    // Manifest'i DHT'ye yayınla
    println!("Manifest DHT'ye yayınlanıyor...");
    tokio::time::timeout(
        Duration::from_secs(30),
        node.put_manifest(&pubkey_hex, manifest_bytes),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Manifest yayınlama zaman aşımı"))?
    .map_err(|e| anyhow::anyhow!("Manifest yayınlama başarısız: {e}"))?;

    // Onion relay anahtarını duyur (bu node onion hedefi/relay'i olabilsin — Manifesto V)
    tokio::time::timeout(Duration::from_secs(20), node.announce_relay_key()).await.ok();

    // Blokları duyur
    println!("Bloklar duyuruluyor ({} CID)...", all_cids.len());
    for cid in &all_cids {
        tokio::time::timeout(
            Duration::from_secs(15),
            node.start_providing(cid),
        )
        .await
        .ok();
    }

    // Etiketleri DHT'ye duyur (Faz 5 — discovery). get→append→put (best-effort).
    if !tag_claims.is_empty() {
        println!("Etiketler duyuruluyor: {}", tags.join(", "));
        for (tag, claim) in &tag_claims {
            let key = tag_dht_key(tag);
            // Mevcut listeyi çek, kendi claim'ini ekle (imzalı), geri yaz.
            let mut claims: Vec<TagClaim> =
                match tokio::time::timeout(Duration::from_secs(15), node.get_dht(&key)).await {
                    Ok(Ok(b)) => ciborium::from_reader(b.as_slice()).unwrap_or_default(),
                    _ => Vec::new(),
                };
            claims.retain(|c| c.target_author != pubkey_bytes || c.tag != *tag);
            claims.push(claim.clone());
            let mut bytes = Vec::new();
            if ciborium::into_writer(&claims, &mut bytes).is_ok() {
                tokio::time::timeout(Duration::from_secs(20), node.put_dht(&key, bytes))
                    .await
                    .ok();
            }
        }
    }

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Site yayınlandı!");
    println!("  Adres: {}", uri);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Ctrl+C ile durdurun. Çalıştığı sürece site erişilebilir.");

    tokio::signal::ctrl_c().await?;
    println!("\nDurduruluyor...");
    Ok(())
}

// ═══════════════════════════════════════════════
// Fetch
// ═══════════════════════════════════════════════

async fn run_fetch(
    uri: String,
    decrypt_key: Option<String>,
    output: String,
    port: u16,
    wait_secs: u64,
    config: AlterNetConfig,
) -> anyhow::Result<()> {
    let output_path = PathBuf::from(&output);

    // URI'den pubkey çıkar
    let pubkey_bytes = alter_uri_to_pubkey(&uri)
        .map_err(|e| anyhow::anyhow!("Geçersiz alter:// URI: {e}"))?;
    let pubkey_hex = pubkey_to_hex(&pubkey_bytes);

    // Geçici keypair (fetch için kimlik şart değil)
    let keypair = libp2p::identity::Keypair::generate_ed25519();

    // Block store
    let blocks_dir = config.blocks_dir();
    let quota = config.effective_storage_quota();
    let store = Arc::new(
        FsBlockStore::new(blocks_dir, quota)
            .await
            .map_err(|e| anyhow::anyhow!("Block store başlatılamadı: {e}"))?,
    );

    // Node başlat
    let node = spawn_node(keypair, config, Arc::clone(&store))
        .await
        .map_err(|e| anyhow::anyhow!("Node başlatılamadı: {e}"))?;
    node.listen_on(port)
        .await
        .map_err(|e| anyhow::anyhow!("Dinleme başlatılamadı: {e}"))?;

    // mDNS keşif için bekle
    println!("Ağ keşfi bekleniyor ({} sn)...", wait_secs);
    tokio::time::sleep(Duration::from_secs(wait_secs)).await;

    // Manifest'i al ve doğrula
    println!("Manifest alınıyor: {}...", &uri[..uri.len().min(60)]);
    let manifest_bytes = tokio::time::timeout(
        Duration::from_secs(60),
        node.get_manifest(&pubkey_hex),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Manifest alma zaman aşımı (60sn) — publisher çevrimiçi mi?"))?
    .map_err(|e| anyhow::anyhow!("Manifest alınamadı: {e}"))?;

    let manifest = deserialize_manifest(&manifest_bytes)
        .map_err(|e| anyhow::anyhow!("Manifest ayrıştırılamadı: {e}"))?;

    // Manifesto VII: imza doğrulaması zorunludur
    verify_manifest(&manifest)
        .map_err(|e| anyhow::anyhow!("Manifest imza doğrulaması başarısız: {e}"))?;

    println!(
        "Manifest doğrulandı (seq={}, yazar={}...)",
        manifest.sequence,
        &pubkey_hex[..16]
    );
    if let Some(title) = &manifest.metadata.title {
        println!("  Başlık: {}", title);
    }

    // Şifreli içerik kontrolü (Manifesto III)
    let content_key = if manifest.metadata.encrypted {
        match &decrypt_key {
            Some(pw) => {
                println!("  İçerik şifreli — çözme anahtarı uygulanacak");
                Some(alternet_core::crypto::derive_content_key(pw))
            }
            None => anyhow::bail!(
                "İçerik şifreli ama --decrypt-key verilmedi. Doğru parolayı sağlayın."
            ),
        }
    } else {
        None
    };

    // DAG'ı indir
    println!("İçerik indiriliyor...");
    fetch_dag_blocks(&node, &store, &manifest.root_cid)
        .await
        .map_err(|e| anyhow::anyhow!("Blok indirme başarısız: {e}"))?;

    // Dosya sistemine çıkar (şifreliyse çöz)
    tokio::fs::create_dir_all(&output_path).await?;
    extract_dag_keyed(&*store, &manifest.root_cid, &output_path, content_key)
        .await
        .map_err(|e| anyhow::anyhow!("İçerik çıkarma başarısız: {e}"))?;

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  İçerik indirildi!");
    println!("  Konum: {}", output_path.display());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    Ok(())
}

// ═══════════════════════════════════════════════
// Pin
// ═══════════════════════════════════════════════

async fn run_pin(
    uri: String,
    port: u16,
    wait_secs: u64,
    config: AlterNetConfig,
) -> anyhow::Result<()> {
    let pubkey_bytes = alter_uri_to_pubkey(&uri)
        .map_err(|e| anyhow::anyhow!("Geçersiz alter:// URI: {e}"))?;
    let pubkey_hex = pubkey_to_hex(&pubkey_bytes);

    let keypair = libp2p::identity::Keypair::generate_ed25519();

    let blocks_dir = config.blocks_dir();
    let quota = config.effective_storage_quota();
    let store = Arc::new(
        FsBlockStore::new(blocks_dir, quota)
            .await
            .map_err(|e| anyhow::anyhow!("Block store başlatılamadı: {e}"))?,
    );

    let node = spawn_node(keypair, config, Arc::clone(&store))
        .await
        .map_err(|e| anyhow::anyhow!("Node başlatılamadı: {e}"))?;
    let listen_addr = node
        .listen_on(port)
        .await
        .map_err(|e| anyhow::anyhow!("Dinleme başlatılamadı: {e}"))?;
    println!("Dinleniyor: {}/p2p/{}", listen_addr, node.local_peer_id());

    println!("Ağ keşfi bekleniyor ({} sn)...", wait_secs);
    tokio::time::sleep(Duration::from_secs(wait_secs)).await;

    // Manifest al + doğrula
    println!("Manifest alınıyor...");
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
        .map_err(|e| anyhow::anyhow!("İmza doğrulaması başarısız: {e}"))?;

    // Tüm blokları indir
    println!("Bloklar indiriliyor...");
    fetch_dag_blocks(&node, &store, &manifest.root_cid)
        .await
        .map_err(|e| anyhow::anyhow!("Blok indirme başarısız: {e}"))?;

    // Bu node'u da provider olarak duyur
    println!("Bu node sağlayıcı olarak duyuruluyor...");
    let all_cids = collect_all_cids(&*store, &manifest.root_cid)
        .await
        .map_err(|e| anyhow::anyhow!("CID toplama başarısız: {e}"))?;
    for cid in &all_cids {
        node.start_providing(cid).await.ok();
    }
    // Onion relay anahtarını duyur (pin'leyen node relay/hedef olabilir)
    tokio::time::timeout(Duration::from_secs(20), node.announce_relay_key()).await.ok();

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Site pin'lendi! ({} blok)", all_cids.len());
    println!("  Adres: {}", uri);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Ctrl+C ile durdurun. Çalıştığı sürece site erişilebilir.");

    tokio::signal::ctrl_c().await?;
    println!("\nDurduruluyor...");
    Ok(())
}

// ═══════════════════════════════════════════════
// DAG Block Fetcher (BFS)
// ═══════════════════════════════════════════════

/// DAG'daki tüm blokları P2P ağından indir, her blokun hash'ini doğrula.
///
/// Manifesto III: Her blok teslim alındığında CID = BLAKE3(veri) doğrulanır.
/// Manifesto V: Gizlilik seviyesine göre padding/delay/onion uygulanır.
async fn fetch_dag_blocks(
    node: &alternet_core::network::NodeHandle,
    store: &FsBlockStore,
    root_cid: &alternet_core::types::Cid,
) -> anyhow::Result<()> {
    use alternet_core::{content::cbor_decode, types::DagNode};
    use std::collections::VecDeque;

    let mut queue: VecDeque<alternet_core::types::Cid> = VecDeque::new();
    queue.push_back(root_cid.clone());

    while let Some(cid) = queue.pop_front() {
        // Zaten varsa atla
        if store
            .has(&cid)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?
        {
            // Çocukları ekle
            if let Ok(Some(data)) = store.get(&cid).await
                && let Ok(node_data) = cbor_decode::<DagNode>(&data) {
                enqueue_children(&mut queue, node_data);
            }
            continue;
        }

        // Sağlayıcıları bul
        let providers = tokio::time::timeout(
            Duration::from_secs(30),
            node.get_providers(&cid),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Sağlayıcı arama zaman aşımı: {}", cid))?
        .map_err(|e| anyhow::anyhow!("Sağlayıcı araması başarısız: {e}"))?;

        if providers.is_empty() {
            anyhow::bail!("Blok için sağlayıcı bulunamadı: {}", cid);
        }

        // Onion gizliliği aktifse relay üzerinden çek (sorgu gizliliği — Manifesto V).
        let use_onion = matches!(
            node.privacy().level,
            alternet_core::routing::PrivacyLevel::Onion { .. }
        );

        // Sırayla dene
        let mut fetched = false;
        for peer in &providers {
            let result = if use_onion {
                onion_fetch_block(node, &cid, *peer).await
            } else {
                tokio::time::timeout(Duration::from_secs(30), node.request_block(*peer, &cid))
                    .await
                    .map_err(|_| anyhow::anyhow!("zaman aşımı"))
                    .and_then(|r| r.map_err(|e| anyhow::anyhow!("{e}")))
            };
            match result {
                Ok(data) => {
                    store
                        .put(&data)
                        .await
                        .map_err(|e| anyhow::anyhow!("Blok depolama başarısız: {e}"))?;
                    if let Ok(node_data) = cbor_decode::<DagNode>(&data) {
                        enqueue_children(&mut queue, node_data);
                    }
                    fetched = true;
                    break;
                }
                Err(e) => tracing::warn!("Peer {} blok veremedi: {}", peer, e),
            }
        }

        if !fetched {
            anyhow::bail!("Blok indirilemedi (tüm sağlayıcılar başarısız): {}", cid);
        }
    }

    Ok(())
}

/// Bir bloğu onion route üzerinden çek (relay keşfi + Sphinx).
///
/// Hedef sağlayıcının ve (varsa) bir ara relay'in X25519 anahtarları DHT'den alınır,
/// route [relay, hedef] olarak kurulur. Anahtar bulunamazsa daha kısa route'a düşer.
/// Manifesto V: sorgulanan CID, geçiş düğümlerinden gizlenir.
async fn onion_fetch_block(
    node: &alternet_core::network::NodeHandle,
    cid: &alternet_core::types::Cid,
    target: libp2p::PeerId,
) -> anyhow::Result<Vec<u8>> {
    use alternet_core::routing::{PrivacyConfig, PrivacyLevel, RelayNode, RoutingLayer};

    // Hedefin relay anahtarı (son onion katmanı buna şifrelenir)
    let target_key = tokio::time::timeout(Duration::from_secs(20), node.get_relay_key(target))
        .await
        .map_err(|_| anyhow::anyhow!("hedef relay anahtarı zaman aşımı"))?
        .map_err(|e| anyhow::anyhow!("hedef relay anahtarı yok: {e}"))?;

    // Bir ara relay seç (hedeften farklı bilinen peer)
    let peers = node.known_peers().await.unwrap_or_default();
    let mut route: Vec<RelayNode> = Vec::new();
    if let Some(relay) = peers.into_iter().find(|p| *p != target)
        && let Ok(Ok(rk)) =
            tokio::time::timeout(Duration::from_secs(15), node.get_relay_key(relay)).await
    {
        route.push(RelayNode { peer_id: relay, x25519_pubkey: rk });
    }
    route.push(RelayNode { peer_id: target, x25519_pubkey: target_key });

    let routing = RoutingLayer::new(PrivacyConfig {
        level: PrivacyLevel::Onion { hops: route.len() as u8 },
        chaff_enabled: false,
        time_blind_enabled: false,
    });
    let first = route[0].peer_id;
    tokio::time::timeout(
        Duration::from_secs(40),
        routing.fetch_block(node, first, cid, Some(&route)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("onion fetch zaman aşımı"))?
    .map_err(|e| anyhow::anyhow!("onion fetch: {e}"))
}

// ═══════════════════════════════════════════════
// Name — AlterNS (petname + zone delegasyonu)
// ═══════════════════════════════════════════════

/// Salt-okuma ağ işlemleri için geçici (kimliksiz) node başlat.
async fn start_ephemeral_node(
    config: &AlterNetConfig,
    port: u16,
    wait_secs: u64,
) -> anyhow::Result<alternet_core::network::NodeHandle> {
    let store = Arc::new(
        FsBlockStore::new(config.blocks_dir(), config.effective_storage_quota())
            .await
            .map_err(|e| anyhow::anyhow!("Block store: {e}"))?,
    );
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let node = spawn_node(keypair, config.clone(), store)
        .await
        .map_err(|e| anyhow::anyhow!("Node: {e}"))?;
    node.listen_on(port).await.map_err(|e| anyhow::anyhow!("Listen: {e}"))?;
    tokio::time::sleep(Duration::from_secs(wait_secs)).await;
    Ok(node)
}

async fn run_name(
    action: NameAction,
    password: Option<&str>,
    config: AlterNetConfig,
) -> anyhow::Result<()> {
    match action {
        NameAction::Set { petname, uri } => {
            let pubkey = alter_uri_to_pubkey(&uri).map_err(|e| anyhow::anyhow!("Geçersiz URI: {e}"))?;
            let mut store = PetnameStore::open(&config.data_dir)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            store.assign(&petname, &pubkey, None).map_err(|e| anyhow::anyhow!("{e}"))?;
            store.save().await.map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("Petname atandı: {petname} → {uri}");
        }
        NameAction::List => {
            let store = PetnameStore::open(&config.data_dir)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let names = store.list();
            if names.is_empty() {
                println!("Kayıtlı petname yok. Ekle: alternet-cli name set <isim> <alter://...>");
            }
            for e in names {
                println!("  {:16} alter://{}", e.name, e.pubkey_hex);
            }
        }
        NameAction::Rm { petname } => {
            let mut store = PetnameStore::open(&config.data_dir)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            store.remove(&petname).map_err(|e| anyhow::anyhow!("{e}"))?;
            store.save().await.map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("Petname silindi: {petname}");
        }
        NameAction::Resolve { name, port, wait_secs } => {
            let store = PetnameStore::open(&config.data_dir)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            // Alt-yol var mı? (zone delegasyonu DHT'den gerekebilir)
            let has_sub = name.trim_start_matches("alter://").contains('/');
            if has_sub {
                println!("DHT'den zone delegasyonları çözülüyor...");
                let node = start_ephemeral_node(&config, port, wait_secs).await?;
                let zones = fetch_zone_chain(&node, &store, &name).await?;
                let resolved = resolve_full_uri(&name, &store, &zones)
                    .map_err(|e| anyhow::anyhow!("Çözülemedi: {e}"))?;
                println!("{name} → {resolved}");
            } else {
                match store.resolve(&name).map_err(|e| anyhow::anyhow!("{e}"))? {
                    Some(r) => println!("{name} → {}", pubkey_to_alter_uri(&r.pubkey)),
                    None => anyhow::bail!("Çözülemedi: '{name}' (yerel petname yok, self-cert değil)"),
                }
            }
        }
        NameAction::Delegate { subname, child_uri, port, wait_secs } => {
            let child = alter_uri_to_pubkey(&child_uri)
                .map_err(|e| anyhow::anyhow!("Geçersiz child URI: {e}"))?;
            warn_if_plaintext(password);
            let keypair = load_identity(config.keyfile_path(), password)
                .map_err(|e| anyhow::anyhow!("Keypair: {e}"))?;
            let parent_hex = pubkey_to_hex(&keypair.public().encode_protobuf());
            let zd = create_zone_delegation(&keypair, subname.clone(), child)
                .map_err(|e| anyhow::anyhow!("Delegasyon: {e}"))?;
            let mut bytes = Vec::new();
            ciborium::into_writer(&zd, &mut bytes)?;

            let node = start_ephemeral_node(&config, port, wait_secs).await?;
            let key = zone_dht_key(&parent_hex, &subname);
            tokio::time::timeout(Duration::from_secs(30), node.put_dht(&key, bytes))
                .await
                .map_err(|_| anyhow::anyhow!("DHT put zaman aşımı"))?
                .map_err(|e| anyhow::anyhow!("DHT put: {e}"))?;
            println!("Zone delegasyonu yayınlandı: {parent_hex}/{subname} → {child_uri}");
        }
        NameAction::Publish { port, wait_secs } => {
            warn_if_plaintext(password);
            let keypair = load_identity(config.keyfile_path(), password)
                .map_err(|e| anyhow::anyhow!("Keypair: {e}"))?;
            let pubkey_hex = pubkey_to_hex(&keypair.public().encode_protobuf());
            let store = PetnameStore::open(&config.data_dir)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let signed = sign_petname_list(&keypair, store.list())
                .map_err(|e| anyhow::anyhow!("İmzalama: {e}"))?;
            let mut bytes = Vec::new();
            ciborium::into_writer(&signed, &mut bytes)?;

            let node = start_ephemeral_node(&config, port, wait_secs).await?;
            let key = petnames_dht_key(&pubkey_hex);
            tokio::time::timeout(Duration::from_secs(30), node.put_dht(&key, bytes))
                .await
                .map_err(|_| anyhow::anyhow!("DHT put zaman aşımı"))?
                .map_err(|e| anyhow::anyhow!("DHT put: {e}"))?;
            println!("Petname listesi DHT'ye yayınlandı ({} kayıt)", store.list().len());
        }
    }
    Ok(())
}

/// `alter://root/sub1/sub2...` için zone delegasyon zincirini DHT'den çekip ZoneStore'a doldur.
async fn fetch_zone_chain(
    node: &alternet_core::network::NodeHandle,
    resolver: &PetnameStore,
    uri: &str,
) -> anyhow::Result<ZoneStore> {
    let mut zones = ZoneStore::new();
    let stripped = uri.trim_start_matches("alter://");
    let mut parts = stripped.split('/');
    let root = parts.next().unwrap_or("");

    // Kök pubkey: petname veya self-cert
    let mut current = match resolver.resolve(root).map_err(|e| anyhow::anyhow!("{e}"))? {
        Some(r) => r.pubkey,
        None => alter_uri_to_pubkey(&format!("alter://{root}"))
            .map_err(|e| anyhow::anyhow!("Kök çözülemedi: {e}"))?,
    };

    for sub in parts {
        if sub.is_empty() {
            continue;
        }
        let parent_hex = pubkey_to_hex(&current);
        let key = zone_dht_key(&parent_hex, sub);
        let bytes = match tokio::time::timeout(Duration::from_secs(20), node.get_dht(&key)).await {
            Ok(Ok(b)) => b,
            _ => break, // delegasyon yok → kalan içerik alt-yolu
        };
        let zd: alternet_core::governance::ZoneDelegation = ciborium::from_reader(bytes.as_slice())
            .map_err(|e| anyhow::anyhow!("Zone decode: {e}"))?;
        zones.add(&zd).map_err(|e| anyhow::anyhow!("Zone doğrulama: {e}"))?;
        current = zd.child_pubkey;
    }
    Ok(zones)
}

// ═══════════════════════════════════════════════
// Search — Etiket keşfi (Faz 5)
// ═══════════════════════════════════════════════

async fn run_search(
    tag: String,
    port: u16,
    wait_secs: u64,
    config: AlterNetConfig,
) -> anyhow::Result<()> {
    let node = start_ephemeral_node(&config, port, wait_secs).await?;
    let key = tag_dht_key(&tag);
    println!("Etiket aranıyor: #{tag}");
    let bytes = match tokio::time::timeout(Duration::from_secs(30), node.get_dht(&key)).await {
        Ok(Ok(b)) => b,
        _ => {
            println!("Bu etiketle kayıt bulunamadı.");
            return Ok(());
        }
    };
    // Kayıt: imzalı TagClaim listesi
    let claims: Vec<TagClaim> = ciborium::from_reader(bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("Etiket kaydı decode: {e}"))?;
    let mut count = 0;
    for claim in &claims {
        if verify_tag_claim(claim).is_ok() && claim.tag == tag {
            println!("  {}", pubkey_to_alter_uri(&claim.target_author));
            count += 1;
        }
    }
    println!("{count} sonuç (imzası doğrulanmış).");
    Ok(())
}

// ═══════════════════════════════════════════════
// App — WASM sandbox (Faz 5)
// ═══════════════════════════════════════════════

fn parse_capability(s: &str) -> Option<Capability> {
    match s.trim().to_lowercase().as_str() {
        "clock" => Some(Capability::Clock),
        "content-read" | "content" => Some(Capability::ContentRead),
        "storage-write" | "storage" => Some(Capability::StorageWrite),
        "network" | "net" => Some(Capability::NetworkAccess),
        _ => None,
    }
}

async fn run_app(
    action: AppAction,
    password: Option<&str>,
    config: AlterNetConfig,
) -> anyhow::Result<()> {
    match action {
        AppAction::Sign { wasm, entry, id, output, caps } => {
            warn_if_plaintext(password);
            let keypair = load_identity(config.keyfile_path(), password)
                .map_err(|e| anyhow::anyhow!("Keypair: {e}"))?;
            let wasm_bytes = std::fs::read(&wasm)?;
            let capabilities: Vec<Capability> =
                caps.iter().filter_map(|c| parse_capability(c)).collect();
            let manifest = create_app_manifest(
                &keypair,
                id,
                "alternet-app".into(),
                "1.0".into(),
                entry,
                capabilities,
                &wasm_bytes,
            )
            .map_err(|e| anyhow::anyhow!("Manifest: {e}"))?;
            let mut bytes = Vec::new();
            ciborium::into_writer(&manifest, &mut bytes)?;
            std::fs::write(&output, &bytes)?;
            println!("Manifest imzalandı: {output}");
        }
        AppAction::Run { wasm, manifest, input, fuel, caps } => {
            let wasm_bytes = std::fs::read(&wasm)?;
            let manifest_bytes = std::fs::read(&manifest)?;
            let manifest: AppManifest = ciborium::from_reader(manifest_bytes.as_slice())
                .map_err(|e| anyhow::anyhow!("Manifest decode: {e}"))?;
            let granted: Vec<Capability> =
                caps.iter().filter_map(|c| parse_capability(c)).collect();
            let policy = alternet_core::apps::AppPolicy::with(granted);
            let host = AppHost::new().map_err(|e| anyhow::anyhow!("WASM host: {e}"))?;
            let result = host
                .run_app(&manifest, &wasm_bytes, &policy, input, fuel)
                .map_err(|e| anyhow::anyhow!("Çalıştırma: {e}"))?;
            println!("Çıktı     : {}", result.output);
            println!("Kalan fuel: {}", result.fuel_remaining);
            for line in &result.log {
                println!("  [log] {line}");
            }
        }
    }
    Ok(())
}

// ═══════════════════════════════════════════════
// Feed — WoT abonelik akışı (Faz 5)
// ═══════════════════════════════════════════════

fn subscriptions_path(config: &AlterNetConfig) -> PathBuf {
    config.data_dir.join("subscriptions.cbor")
}

fn load_subscriptions(config: &AlterNetConfig) -> Vec<String> {
    let path = subscriptions_path(config);
    std::fs::read(&path)
        .ok()
        .and_then(|b| ciborium::from_reader::<Vec<String>, _>(b.as_slice()).ok())
        .unwrap_or_default()
}

fn save_subscriptions(config: &AlterNetConfig, subs: &[String]) -> anyhow::Result<()> {
    let path = subscriptions_path(config);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut bytes = Vec::new();
    ciborium::into_writer(&subs.to_vec(), &mut bytes)?;
    std::fs::write(&path, bytes)?;
    Ok(())
}

async fn run_feed(action: FeedAction, config: AlterNetConfig) -> anyhow::Result<()> {
    match action {
        FeedAction::Subscribe { uri } => {
            alter_uri_to_pubkey(&uri).map_err(|e| anyhow::anyhow!("Geçersiz URI: {e}"))?;
            let mut subs = load_subscriptions(&config);
            if !subs.contains(&uri) {
                subs.push(uri.clone());
                save_subscriptions(&config, &subs)?;
            }
            println!("Abone olundu: {uri}");
        }
        FeedAction::Unsubscribe { uri } => {
            let mut subs = load_subscriptions(&config);
            subs.retain(|s| s != &uri);
            save_subscriptions(&config, &subs)?;
            println!("Abonelikten çıkıldı: {uri}");
        }
        FeedAction::List => {
            let subs = load_subscriptions(&config);
            if subs.is_empty() {
                println!("Abonelik yok. Ekle: alternet-cli feed subscribe alter://KEY");
            }
            for s in subs {
                println!("  {s}");
            }
        }
        FeedAction::Pull { port, wait_secs } => {
            let subs = load_subscriptions(&config);
            if subs.is_empty() {
                println!("Abonelik yok.");
                return Ok(());
            }
            let node = start_ephemeral_node(&config, port, wait_secs).await?;
            println!("Akış toplanıyor ({} yazar)...", subs.len());
            for uri in &subs {
                let pubkey = match alter_uri_to_pubkey(uri) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let pubkey_hex = pubkey_to_hex(&pubkey);
                match tokio::time::timeout(Duration::from_secs(30), node.get_manifest(&pubkey_hex))
                    .await
                {
                    Ok(Ok(bytes)) => match deserialize_manifest(&bytes) {
                        Ok(m) if verify_manifest(&m).is_ok() => {
                            let title = m.metadata.title.unwrap_or_else(|| "(başlıksız)".into());
                            println!("  ✓ {uri}");
                            println!("      seq={} başlık=\"{}\"", m.sequence, title);
                        }
                        _ => println!("  ✗ {uri} (manifest geçersiz)"),
                    },
                    _ => println!("  … {uri} (ulaşılamadı)"),
                }
            }
        }
    }
    Ok(())
}

// ═══════════════════════════════════════════════
// Board — CRDT forum/wiki (Faz 5, DHT snapshot)
// ═══════════════════════════════════════════════

fn board_dht_key(board_id: &str) -> String {
    format!("/alternet/board/{board_id}")
}

async fn run_board(
    action: BoardAction,
    password: Option<&str>,
    config: AlterNetConfig,
) -> anyhow::Result<()> {
    match action {
        BoardAction::Post { board_id, title, body, port, wait_secs } => {
            warn_if_plaintext(password);
            let keypair = load_identity(config.keyfile_path(), password)
                .map_err(|e| anyhow::anyhow!("Keypair: {e}"))?;
            let author = pubkey_to_alter_uri(&keypair.public().encode_protobuf());

            let node = start_ephemeral_node(&config, port, wait_secs).await?;
            let key = board_dht_key(&board_id);

            // Mevcut snapshot'ı çek (yoksa genesis oluştur) → CRDT determinist merge için
            // tüm yayıncılar aynı snapshot'tan türer.
            let mut board = match tokio::time::timeout(Duration::from_secs(20), node.get_dht(&key))
                .await
            {
                Ok(Ok(bytes)) => CrdtBoard::load(&board_id, &bytes)
                    .map_err(|e| anyhow::anyhow!("Board yüklenemedi: {e}"))?,
                _ => CrdtBoard::new(&board_id),
            };

            // Benzersiz girdi id'si (zaman + yazar)
            let entry_id = format!("{}-{}", alternet_core::governance::now_ms(), &author[8..16]);
            board
                .add_entry(&entry_id, &author, &title, &body)
                .map_err(|e| anyhow::anyhow!("Girdi eklenemedi: {e}"))?;

            let bytes = board.save();
            tokio::time::timeout(Duration::from_secs(30), node.put_dht(&key, bytes))
                .await
                .map_err(|_| anyhow::anyhow!("DHT put zaman aşımı"))?
                .map_err(|e| anyhow::anyhow!("DHT put: {e}"))?;
            println!("Board girdisi yayınlandı: {board_id} ← \"{title}\"");
        }
        BoardAction::Read { board_id, port, wait_secs } => {
            let node = start_ephemeral_node(&config, port, wait_secs).await?;
            let key = board_dht_key(&board_id);
            let bytes = match tokio::time::timeout(Duration::from_secs(20), node.get_dht(&key)).await
            {
                Ok(Ok(b)) => b,
                _ => {
                    println!("Board bulunamadı: {board_id}");
                    return Ok(());
                }
            };
            let board = CrdtBoard::load(&board_id, &bytes)
                .map_err(|e| anyhow::anyhow!("Board yüklenemedi: {e}"))?;
            let entries = board.entries().map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("Board: {board_id} ({} girdi)", entries.len());
            for e in entries {
                println!("  ─ \"{}\" — {}", e.title, &e.author[..e.author.len().min(24)]);
                println!("    {}", e.body);
            }
        }
    }
    Ok(())
}

fn parse_privacy_level(s: &str) -> PrivacyLevel {
    match s.trim().to_lowercase().as_str() {
        "clear" | "none" => PrivacyLevel::Clear,
        "onion" => PrivacyLevel::Onion { hops: 3 },
        "tor" => PrivacyLevel::Tor,
        _ => PrivacyLevel::Padded, // varsayılan
    }
}

fn enqueue_children(
    queue: &mut std::collections::VecDeque<alternet_core::types::Cid>,
    node: alternet_core::types::DagNode,
) {
    match node {
        alternet_core::types::DagNode::Leaf { .. } => {}
        alternet_core::types::DagNode::Internal { links, .. } => {
            queue.extend(links);
        }
        alternet_core::types::DagNode::Directory { entries } => {
            queue.extend(entries.into_iter().map(|e| e.cid));
        }
    }
}

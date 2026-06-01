//! # AlterNet Node Configuration
//!
//! Dosya tabanlı yapılandırma — hesap yok, kayıt yok.
//!
//! **Manifesto I:** Hiçbir hesap veya kayıt gerektirmez.
//! **Manifesto VI:** Varsayılanlar yeterlidir, yapılandırma opsiyoneldir.
//! **Manifesto II:** Güçlü makine daha fazla taşır, zayıf makine kendini taşır.

use crate::routing::PrivacyLevel;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// AlterNet node yapılandırması.
///
/// Hesap alanı yoktur — Manifesto I.
/// Varsayılanlar tek tıkla çalışmaya yeter — Manifesto VI.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlterNetConfig {
    /// Veri dizini (bloklar, anahtar, manifest'ler burada saklanır).
    pub data_dir: PathBuf,

    /// Dinleme portu (0 = rastgele).
    pub listen_port: u16,

    /// Depolama kotası (bytes). 0 = adaptif varsayılan.
    pub storage_quota: u64,

    /// Bootstrap node adresleri (opsiyonel — Manifesto I: otorite değil).
    pub bootstrap_addrs: Vec<String>,

    /// mDNS yerel keşif etkin mi (varsayılan: true — Manifesto VI: zero-config).
    pub mdns_enabled: bool,

    /// DHT server modu (varsayılan: false, alternet-node için true).
    pub dht_server_mode: bool,

    /// Relay hizmeti sunulsun mu (varsayılan: false — Manifesto II: gönüllü).
    pub relay_enabled: bool,

    /// Gizlilik seviyesi (varsayılan: Padded — Manifesto III: güvenlik varsayılandır).
    pub privacy_level: PrivacyLevel,

    /// Tor transport etkin mi (varsayılan: false — `tor` daemon gerektirir).
    ///
    /// Etkinleştirildiğinde tüm giden bağlantılar Tor üzerinden yapılır.
    /// Manifesto V: IP adresi ağa gizlenir.
    pub tor_enabled: bool,

    /// Chaff (sahte) trafik etkin mi (varsayılan: true — Manifesto V).
    pub chaff_enabled: bool,
}

impl Default for AlterNetConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            listen_port: 0,
            storage_quota: 0, // 0 = adaptif
            bootstrap_addrs: Vec::new(),
            mdns_enabled: true,
            dht_server_mode: false,
            relay_enabled: false,
            // Manifesto III: güvenlik varsayılandır
            privacy_level: PrivacyLevel::Padded,
            tor_enabled: false,
            chaff_enabled: true,
        }
    }
}

impl AlterNetConfig {
    /// Yapılandırmayı TOML dosyasından yükle. Dosya yoksa varsayılan döndür.
    pub fn load_or_default<P: AsRef<Path>>(path: P) -> Self {
        std::fs::read_to_string(path.as_ref())
            .ok()
            .and_then(|s| toml_from_str(&s))
            .unwrap_or_default()
    }

    /// Efektif depolama kotasını hesapla.
    /// 0 ise adaptif: mevcut boş alanın %5'i, min 512MB, max 50GB.
    ///
    /// Manifesto II: "Güçlü makine ağın daha fazla içeriğini taşır."
    pub fn effective_storage_quota(&self) -> u64 {
        if self.storage_quota > 0 {
            return self.storage_quota;
        }
        adaptive_storage_quota(&self.data_dir)
    }

    /// Blok deposu dizini.
    pub fn blocks_dir(&self) -> PathBuf {
        self.data_dir.join("blocks")
    }

    /// Anahtar dosyası yolu.
    pub fn keyfile_path(&self) -> PathBuf {
        self.data_dir.join("identity.key")
    }

    /// Manifest cache dizini.
    pub fn manifests_dir(&self) -> PathBuf {
        self.data_dir.join("manifests")
    }

    /// Petname veritabanı yolu.
    pub fn petnames_path(&self) -> PathBuf {
        self.data_dir.join("petnames.cbor")
    }

    /// Gizlilik yapılandırmasını (`RoutingLayer` için) bu config'ten türet.
    ///
    /// Manifesto III: güvenlik varsayılandır — `privacy_level` Clear değilse
    /// time-blind gecikme ve chaff varsayılan olarak açıktır.
    pub fn privacy_config(&self) -> crate::routing::PrivacyConfig {
        crate::routing::PrivacyConfig {
            level: self.privacy_level.clone(),
            chaff_enabled: self.chaff_enabled,
            time_blind_enabled: !matches!(self.privacy_level, PrivacyLevel::Clear),
        }
    }
}

/// Adaptif depolama kotası: mevcut boş alanın %5'i.
fn adaptive_storage_quota(data_dir: &Path) -> u64 {
    use sysinfo::Disks;
    let disks = Disks::new_with_refreshed_list();

    let target = data_dir.to_string_lossy();
    let available = disks
        .iter()
        .filter(|d| target.starts_with(&d.mount_point().to_string_lossy().to_string()))
        .map(|d| d.available_space())
        .max()
        .unwrap_or(10 * 1024 * 1024 * 1024); // varsayılan 10GB

    let quota = available / 20; // %5
    quota.clamp(
        crate::types::MIN_STORAGE_QUOTA,
        crate::types::MAX_STORAGE_QUOTA,
    )
}

/// Varsayılan veri dizini.
fn default_data_dir() -> PathBuf {
    dirs_default()
}

fn dirs_default() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".alternet")
    } else {
        PathBuf::from(".alternet")
    }
}

/// Basit TOML parser (serde_json üzerinden workaround — tam toml crate eklenebilir).
fn toml_from_str(s: &str) -> Option<AlterNetConfig> {
    // Basit anahtar=değer parse. Production'da `toml` crate kullanılır.
    let mut config = AlterNetConfig::default();

    for line in s.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some((key, val)) = line.split_once('=') {
            let key = key.trim();
            let val = val.trim().trim_matches('"');
            match key {
                "data_dir" => config.data_dir = PathBuf::from(val),
                "listen_port" => {
                    if let Ok(p) = val.parse() {
                        config.listen_port = p;
                    }
                }
                "storage_quota" => {
                    if let Ok(q) = val.parse() {
                        config.storage_quota = q;
                    }
                }
                "mdns_enabled" => config.mdns_enabled = val == "true",
                "dht_server_mode" => config.dht_server_mode = val == "true",
                "relay_enabled" => config.relay_enabled = val == "true",
                "tor_enabled" => config.tor_enabled = val == "true",
                "chaff_enabled" => config.chaff_enabled = val == "true",
                "privacy_level" => {
                    config.privacy_level = match val {
                        "clear" => PrivacyLevel::Clear,
                        "padded" => PrivacyLevel::Padded,
                        "onion" => PrivacyLevel::Onion { hops: 3 },
                        "tor" => PrivacyLevel::Tor,
                        _ => PrivacyLevel::Padded,
                    };
                }
                _ => {}
            }
        }
    }

    Some(config)
}

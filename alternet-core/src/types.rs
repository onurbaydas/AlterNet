//! # AlterNet Core Types
//!
//! Tüm modüllerin paylaştığı ortak tipler: `Cid`, `DagNode`, `Manifest`.
//!
//! **Manifesto VII:** İçeriğin bütünlüğü hash ile, kimliği imza ile garanti edilir.
//! Bu modüldeki tipler bu garantiyi veri yapısı seviyesinde uygular.

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════
// CID — İçerik Adresi
// ═══════════════════════════════════════════════

/// İçerik adresi — BLAKE3 hash'in 32-byte çıktısı.
///
/// Manifesto VII: "İçeriğin bütünlüğü hash ile garanti edilir."
/// Bir CID, verinin parmak izidir. Veri değişirse CID değişir.
/// Bu, sahte içerik enjeksiyonunu matematiksel olarak imkânsız kılar.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Cid(pub [u8; 32]);

impl Cid {
    /// Veriden CID oluştur (BLAKE3 hash).
    pub fn from_data(data: &[u8]) -> Self {
        Self(*blake3::hash(data).as_bytes())
    }

    /// Verinin bu CID'e ait olduğunu doğrula.
    pub fn verify(&self, data: &[u8]) -> bool {
        Self::from_data(data) == *self
    }

    /// CID'i hex string'e dönüştür.
    pub fn to_hex(&self) -> String {
        data_encoding::HEXLOWER.encode(&self.0)
    }

    /// Hex string'den CID oluştur.
    pub fn from_hex(hex: &str) -> crate::error::Result<Self> {
        let bytes = data_encoding::HEXLOWER
            .decode(hex.as_bytes())
            .map_err(|e| crate::error::AlterNetError::CborDecode(format!("invalid CID hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(crate::error::AlterNetError::CborDecode(format!(
                "CID must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl std::fmt::Debug for Cid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cid({})", &self.to_hex()[..16])
    }
}

impl std::fmt::Display for Cid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// ═══════════════════════════════════════════════
// DAG Düğümleri
// ═══════════════════════════════════════════════

/// Merkle DAG düğümü.
///
/// Üç çeşidi vardır:
/// - `Leaf`: ham veri bloğu (≤256KB)
/// - `Internal`: dosya chunk'larının CID listesi (büyük dosyalar için)
/// - `Directory`: isim → CID eşlemeleri (dizin yapısı)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DagNode {
    /// Yaprak düğüm: ham veri bloğu (≤256KB).
    Leaf {
        data: Vec<u8>,
    },
    /// Dahili düğüm: bir dosyanın chunk CID'leri.
    Internal {
        /// Çocuk blokların CID'leri (sıralı).
        links: Vec<Cid>,
        /// Alt-ağacın toplam boyutu (bytes).
        total_size: u64,
    },
    /// Dizin düğümü: dosya/alt-dizin eşlemeleri.
    Directory {
        entries: Vec<DirEntry>,
    },
}

/// Dizin içindeki bir giriş.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirEntry {
    /// Dosya/dizin adı.
    pub name: String,
    /// İçeriğin CID'i (dosya veya alt-dizin kökü).
    pub cid: Cid,
    /// Toplam boyut (bytes).
    pub size: u64,
    /// Dizin mi, dosya mı?
    pub is_dir: bool,
}

// ═══════════════════════════════════════════════
// Manifest — İmzalı Site Anlık Görüntüsü
// ═══════════════════════════════════════════════

/// İmzalı manifest — bir sitenin anlık görüntüsü.
///
/// Manifesto VII: "Kod söz verir" — imza asla devre dışı bırakılamaz.
/// Her manifest yayıncının Ed25519 anahtarıyla imzalanır.
/// `sequence` monoton artan: replay/rollback saldırılarını engeller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Manifest format sürümü (şu an = 1).
    pub version: u8,
    /// Yayıncının Ed25519 public key'i (protobuf encoded).
    pub author: Vec<u8>,
    /// Monoton artan sıra numarası (replay koruması).
    pub sequence: u64,
    /// Merkle DAG kök CID'i.
    pub root_cid: Cid,
    /// Oluşturulma zamanı (unix epoch seconds, bilgi amaçlı).
    pub created_at: u64,
    /// Site metadata.
    pub metadata: ManifestMeta,
    /// Ed25519 imza (signing_bytes üzerinde).
    pub signature: Vec<u8>,
}

/// Site metadata — başlık, açıklama, MIME tipi, etiketler.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestMeta {
    pub title: Option<String>,
    pub description: Option<String>,
    /// Varsayılan MIME tipi ("text/html").
    pub mime_type: Option<String>,
    /// Keşif etiketleri (Faz 5 — discovery.rs etiket indeksi).
    ///
    /// Yayıncı sitesini konu/etiketlerle işaretler; `discovery.rs` bunları DHT'de
    /// `tag → [author]` indeksine yazar. `#[serde(default)]` ile eski manifest'lerle
    /// geriye uyumlu (CBOR — Manifesto II).
    #[serde(default)]
    pub tags: Vec<String>,

    /// İçerik opsiyonel olarak simetrik şifreli mi? (Manifesto III — ek katman).
    ///
    /// `true` ise bloklar `crypto::encrypt_content` ile şifrelenmiştir; alıcı içerik
    /// anahtarını (passphrase) yan kanaldan edinmelidir. Anahtar manifest'te **tutulmaz**.
    /// Bu bir kapatma bayrağı değildir — transport şifrelemesi her hâlükârda açıktır.
    #[serde(default)]
    pub encrypted: bool,
}

// ═══════════════════════════════════════════════
// Sabitler
// ═══════════════════════════════════════════════

/// Chunk boyutu: 256KB (AlterChat Sharder::CHUNK_SIZE ile uyumlu).
pub const CHUNK_SIZE: usize = 256 * 1024;

/// Varsayılan minimum depolama kotası: 512MB.
pub const MIN_STORAGE_QUOTA: u64 = 512 * 1024 * 1024;

/// Varsayılan maksimum depolama kotası: 50GB.
pub const MAX_STORAGE_QUOTA: u64 = 50 * 1024 * 1024 * 1024;

/// AlterNet protokol string'i.
pub const PROTOCOL_VERSION: &str = "/alternet/1.0.0";

/// AlterNet exchange protokol string'i.
pub const EXCHANGE_PROTOCOL: &str = "/alternet/exchange/1.0.0";

/// Tek bir blok için izin verilen maksimum boyut (DoS koruması).
///
/// Bir blok en fazla bir chunk (256KB) + DAG düğüm overhead'i + opsiyonel şifreleme
/// payı kadardır. 1MB güvenli üst sınır; daha büyük "blok" sunan/isteyen peer reddedilir.
/// Manifesto V: kaynak tüketimi saldırısına karşı sertleşme.
pub const MAX_BLOCK_SIZE: usize = 1024 * 1024;

/// Bir DAG fetch'inde izin verilen maksimum toplam blok sayısı (sonsuz DAG / amplifikasyon
/// saldırısına karşı). Aşılırsa fetch durdurulur.
pub const MAX_DAG_BLOCKS: usize = 1_000_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cid_from_data_and_verify() {
        let data = b"Manifesto VII: kod yalan soylemez";
        let cid = Cid::from_data(data);
        assert!(cid.verify(data));
        assert!(!cid.verify(b"tampered data"));
    }

    #[test]
    fn cid_hex_round_trip() {
        let cid = Cid::from_data(b"test");
        let hex = cid.to_hex();
        let cid2 = Cid::from_hex(&hex).unwrap();
        assert_eq!(cid, cid2);
    }

    #[test]
    fn cid_debug_truncated() {
        let cid = Cid::from_data(b"test");
        let debug = format!("{:?}", cid);
        assert!(debug.starts_with("Cid("));
        assert!(debug.len() < 30); // truncated
    }
}

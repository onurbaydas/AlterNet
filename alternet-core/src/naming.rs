//! # AlterNet AlterNS — DNS'siz İsimlendirme Sistemi (L2)
//!
//! Merkezi DNS, registrar veya global namespace olmadan isim çözümü.
//!
//! **Manifesto I:** Hiçbir registrar, DNS sunucusu veya global otorite yoktur.
//! **Manifesto IV:** İsimler yereldir ve Web of Trust üzerinden çözülür.
//! **Manifesto VI:** `alter://alice` gibi petname'ler sıradan kullanıcılar içindir.
//!
//! ## İsim Çözümleme Zinciri
//!
//! ```text
//! alter://alice/blog
//!   1. Yerel PetnameStore → "alice" → pubkey A
//!   2. alter://<A>/blog  (subpath delegasyonu)
//! ```
//!
//! Self-certifying adresler (`alter://<base32(pubkey)>`) her zaman tek doğru
//! çözüme sahiptir — matematik garanti eder.
//!
//! ## Tehdit Modeli
//! - **Korunan:** Global squatting (yerel isimler — başkasının "alice"si sizin "alice"niz değil)
//! - **Korunan:** İsim sahteciliği (self-certifying adresler kriptografik bağ içerir)
//! - **Sınır:** Petname keşfi sosyal — doğru pubkey'i bulmak güven gerektiriyor
//! - **Sınır:** WoT derinliği artınca sybil saldırısı riski artar (max_depth=3 ile sınırlandırılmış)

use crate::error::{AlterNetError, Result};
use crate::governance::{TrustEdge, ZoneDelegation, verify_trust_edge, verify_zone_delegation};
use crate::identity::alter_uri_to_pubkey;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

// ═══════════════════════════════════════════════
// Tipler
// ═══════════════════════════════════════════════

/// Yerel petname kaydı (kalıcı depolama birimi).
///
/// Manifesto IV: İsimler yerel — global namespace yoktur, squatting yoktur.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PetnameEntry {
    /// İnsan okunabilir kısa isim (ör. "alice", "haberler").
    pub name: String,
    /// Hedef public key (protobuf encoded bytes, hex string olarak saklanır).
    pub pubkey_hex: String,
    /// İsteğe bağlı not (ör. "Alice'in kişisel sitesi").
    pub note: Option<String>,
}

/// İsim çözümleme sonucu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedName {
    /// Çözümlenen public key (protobuf encoded bytes).
    pub pubkey: Vec<u8>,
    /// Kaynağı: "direct" (petname) veya "wot:<depth>" (Web of Trust üzerinden).
    pub source: String,
}

// ═══════════════════════════════════════════════
// NameResolver Trait
// ═══════════════════════════════════════════════

/// İsim çözümleme soyutlaması.
///
/// Manifesto IV: "Güven dayatılmaz, inşa edilir."
pub trait NameResolver {
    /// İnsan okunabilir ismi pubkey'e çözümle.
    fn resolve(&self, name: &str) -> Result<Option<ResolvedName>>;

    /// Petname ata.
    fn assign(&mut self, name: &str, pubkey: &[u8], note: Option<String>) -> Result<()>;

    /// Petname sil.
    fn remove(&mut self, name: &str) -> Result<()>;

    /// Tüm petname'leri listele.
    fn list(&self) -> Vec<PetnameEntry>;
}

// ═══════════════════════════════════════════════
// PetnameStore — Yerel İsim Deposu
// ═══════════════════════════════════════════════

/// Dosya sistemi tabanlı petname deposu.
///
/// Kayıtlar CBOR olarak `<data_dir>/petnames.cbor` konumunda saklanır.
/// Her cihaz kendi isim eşlemesini yönetir — merkezi kayıt yok.
#[derive(Debug)]
pub struct PetnameStore {
    entries: HashMap<String, PetnameEntry>,
    path: Option<PathBuf>,
}

impl PetnameStore {
    /// Bellekte petname deposu (testler için).
    pub fn in_memory() -> Self {
        Self { entries: HashMap::new(), path: None }
    }

    /// Dosya tabanlı petname deposu. Mevcut dosya varsa yükler.
    pub async fn open(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join("petnames.cbor");
        let entries = if path.exists() {
            let bytes = tokio::fs::read(&path).await.map_err(AlterNetError::Io)?;
            let list: Vec<PetnameEntry> = ciborium::from_reader(bytes.as_slice())
                .map_err(|e| AlterNetError::CborDecode(e.to_string()))?;
            list.into_iter().map(|e| (e.name.clone(), e)).collect()
        } else {
            HashMap::new()
        };
        Ok(Self { entries, path: Some(path) })
    }

    /// Tüm kayıtları diske yaz.
    pub async fn save(&self) -> Result<()> {
        let Some(ref path) = self.path else { return Ok(()) };
        let list: Vec<&PetnameEntry> = self.entries.values().collect();
        let mut buf = Vec::new();
        ciborium::into_writer(&list, &mut buf)
            .map_err(|e| AlterNetError::CborEncode(e.to_string()))?;
        // Üst dizini oluştur
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(AlterNetError::Io)?;
        }
        tokio::fs::write(path, &buf).await.map_err(AlterNetError::Io)
    }

    /// İsmi doğrudan çözümle (WoT olmadan).
    pub fn resolve_direct(&self, name: &str) -> Option<&PetnameEntry> {
        // 1. Doğrudan isim araması
        if let Some(e) = self.entries.get(name) {
            return Some(e);
        }
        // 2. self-certifying `alter://...` URI ise pubkey_hex olarak ara
        if name.starts_with("alter://") {
            return self.entries.values().find(|e| {
                let uri = format!("alter://{}", e.pubkey_hex);
                uri == name
            });
        }
        None
    }
}

impl NameResolver for PetnameStore {
    fn resolve(&self, name: &str) -> Result<Option<ResolvedName>> {
        // self-certifying alter:// URI doğrudan çözülür
        if name.starts_with("alter://") {
            // Subpath var mı? alter://key/subpath → sadece key kısmını çöz
            let base = name.trim_start_matches("alter://");
            let key_part = base.split('/').next().unwrap_or(base);
            let alter_uri = format!("alter://{}", key_part);
            match alter_uri_to_pubkey(&alter_uri) {
                Ok(pubkey) => {
                    return Ok(Some(ResolvedName { pubkey, source: "self-cert".into() }));
                }
                Err(e) => {
                    return Err(AlterNetError::ManifestInvalid(format!(
                        "geçersiz alter:// URI: {e}"
                    )));
                }
            }
        }

        // Petname araması
        if let Some(entry) = self.entries.get(name) {
            let pubkey = data_encoding::HEXLOWER
                .decode(entry.pubkey_hex.as_bytes())
                .map_err(|e| AlterNetError::ManifestInvalid(format!("hex decode: {e}")))?;
            return Ok(Some(ResolvedName { pubkey, source: "direct".into() }));
        }

        Ok(None)
    }

    fn assign(&mut self, name: &str, pubkey: &[u8], note: Option<String>) -> Result<()> {
        validate_petname(name)?;
        let pubkey_hex = data_encoding::HEXLOWER.encode(pubkey);
        self.entries.insert(name.to_string(), PetnameEntry {
            name: name.to_string(),
            pubkey_hex,
            note,
        });
        Ok(())
    }

    fn remove(&mut self, name: &str) -> Result<()> {
        self.entries.remove(name);
        Ok(())
    }

    fn list(&self) -> Vec<PetnameEntry> {
        self.entries.values().cloned().collect()
    }
}

// ═══════════════════════════════════════════════
// WoT Çözümleyici
// ═══════════════════════════════════════════════

/// Web of Trust tabanlı isim çözümleyici.
///
/// Kendi petname deposuna ek olarak, güvenilen peer'ların **yayınladığı** petname
/// kayıtlarını güven grafiği üzerinden BFS ile tarar. "Güvendiğim kişilerin X dediği
/// anahtar" mantığını uygular.
///
/// `trust_graph`: truster_pubkey_hex → [(trusted_pubkey_hex, score)]. Pubkey-merkezli
/// (PeerId değil) — petname kayıtları pubkey ile anahtarlandığından tutarlı çözüm sağlar.
///
/// `peer_petnames`: peer_pubkey_hex → o peer'ın yayınladığı petname kayıtları.
/// Üretimde `discovery.rs` bu haritayı DHT `/alternet/petnames/{pubkey}` kayıtlarından
/// doldurur; testlerde elle `ingest_peer_petnames` ile beslenir.
///
/// Manifesto IV: "Güven imzalı kriptografik kanıtlarla inşa edilir." — global otorite yok.
pub struct WotResolver {
    pub petnames: PetnameStore,
    /// truster_pubkey_hex → Vec<(trusted_pubkey_hex, score)>
    trust_graph: HashMap<String, Vec<(String, i32)>>,
    /// peer_pubkey_hex → o peer'ın yayınladığı petname kayıtları
    peer_petnames: HashMap<String, Vec<PetnameEntry>>,
    /// BFS maksimum derinlik (sybil saldırısı yüzeyini sınırlar)
    pub max_depth: usize,
    /// Yerel kullanıcının pubkey hex'i (BFS başlangıç noktası)
    local_pubkey_hex: String,
}

impl WotResolver {
    /// Yeni WoT çözümleyici. `local_pubkey_hex` BFS'in başladığı düğümdür.
    pub fn new(petnames: PetnameStore, local_pubkey_hex: impl Into<String>) -> Self {
        Self {
            petnames,
            trust_graph: HashMap::new(),
            peer_petnames: HashMap::new(),
            max_depth: 3,
            local_pubkey_hex: local_pubkey_hex.into(),
        }
    }

    /// Güven kenarı ekle (pubkey-merkezli). Score > 0 = güvenilir.
    ///
    /// Manifesto IV: güven yereldir; kullanıcı kime ne kadar güvendiğine kendi karar verir.
    pub fn add_trust(&mut self, truster_pubkey: &[u8], trusted_pubkey: &[u8], score: i32) {
        let from = data_encoding::HEXLOWER.encode(truster_pubkey);
        let to = data_encoding::HEXLOWER.encode(trusted_pubkey);
        self.trust_graph.entry(from).or_default().push((to, score));
    }

    /// İmzalı bir `TrustEdge`'i doğrulayıp güven grafiğine ekle.
    ///
    /// `TrustEdge.to_peer_id` bir PeerId string olduğundan, hedefin pubkey'i ayrıca verilir
    /// (petname kayıtları pubkey ile anahtarlanır). İmza `from_public_key` ile doğrulanır.
    pub fn add_trust_edge(&mut self, edge: &TrustEdge, trusted_pubkey: &[u8]) -> Result<()> {
        verify_trust_edge(edge).map_err(AlterNetError::Crypto)?;
        self.add_trust(&edge.from_public_key, trusted_pubkey, edge.score);
        Ok(())
    }

    /// Bir peer'ın yayınladığı petname kayıtlarını içe al (üretimde DHT'den).
    pub fn ingest_peer_petnames(&mut self, peer_pubkey: &[u8], entries: Vec<PetnameEntry>) {
        let hex = data_encoding::HEXLOWER.encode(peer_pubkey);
        self.peer_petnames.insert(hex, entries);
    }

    /// WoT üzerinden isim çöz: yerel düğümden başlayarak güven grafiğinde BFS yap,
    /// ulaşılan güvenilir peer'ların yayınladığı petname kayıtlarında `name` ara.
    ///
    /// İlk eşleşen (en yakın güven mesafesindeki) kayıt kazanır. Score ≤ 0 olan
    /// kenarlar atlanır. `max_depth` ile derinlik sınırlanır (sybil yüzeyi).
    pub fn resolve_wot(&self, name: &str) -> Option<ResolvedName> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(String, usize)> = VecDeque::new();

        visited.insert(self.local_pubkey_hex.clone());
        queue.push_back((self.local_pubkey_hex.clone(), 0));

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= self.max_depth {
                continue;
            }
            let Some(edges) = self.trust_graph.get(&current) else { continue };

            for (trusted_hex, score) in edges {
                if *score <= 0 || visited.contains(trusted_hex) {
                    continue;
                }
                visited.insert(trusted_hex.clone());

                // Bu güvenilir peer `name`'i yayınlamış mı?
                if let Some(entries) = self.peer_petnames.get(trusted_hex)
                    && let Some(entry) = entries.iter().find(|e| e.name == name)
                    && let Ok(pubkey) = data_encoding::HEXLOWER.decode(entry.pubkey_hex.as_bytes())
                {
                    return Some(ResolvedName {
                        pubkey,
                        source: format!("wot:{}", depth + 1),
                    });
                }

                queue.push_back((trusted_hex.clone(), depth + 1));
            }
        }

        None
    }
}

impl NameResolver for WotResolver {
    fn resolve(&self, name: &str) -> Result<Option<ResolvedName>> {
        // Önce doğrudan çözümle (yerel petname / self-cert URI)
        if let Some(resolved) = self.petnames.resolve(name)? {
            return Ok(Some(resolved));
        }
        // Sonra Web of Trust üzerinden çöz
        Ok(self.resolve_wot(name))
    }

    fn assign(&mut self, name: &str, pubkey: &[u8], note: Option<String>) -> Result<()> {
        self.petnames.assign(name, pubkey, note)
    }

    fn remove(&mut self, name: &str) -> Result<()> {
        self.petnames.remove(name)
    }

    fn list(&self) -> Vec<PetnameEntry> {
        self.petnames.list()
    }
}

// ═══════════════════════════════════════════════
// Alter:// URI Çözümleme
// ═══════════════════════════════════════════════

/// `alter://` URI'den temel adresi ve alt-yolu ayrıştır.
///
/// - `alter://abc123` → `(alter://abc123, None)`
/// - `alter://abc123/blog` → `(alter://abc123, Some("blog"))`
/// - `alter://alice/posts` → resolver üzerinden `(alter://<pubkey>, Some("posts"))`
pub fn parse_alter_uri(uri: &str) -> Result<(String, Option<String>)> {
    let stripped = uri
        .strip_prefix("alter://")
        .ok_or_else(|| AlterNetError::ManifestInvalid("alter:// öneki gerekli".into()))?;

    let (key_part, subpath) = if let Some(idx) = stripped.find('/') {
        (&stripped[..idx], Some(stripped[idx + 1..].to_string()))
    } else {
        (stripped, None)
    };

    let base_uri = format!("alter://{}", key_part);
    Ok((base_uri, subpath))
}

/// Petname veya self-certifying URI'yi tam `alter://<pubkey>` adresine çözümle.
pub fn resolve_to_alter_uri(name: &str, resolver: &dyn NameResolver) -> Result<String> {
    // Zaten bir alter:// URI mi?
    if name.starts_with("alter://") {
        let (base, _) = parse_alter_uri(name)?;
        return Ok(base);
    }

    // Petname çözümle
    match resolver.resolve(name)? {
        Some(resolved) => {
            use crate::identity::pubkey_to_alter_uri;
            Ok(pubkey_to_alter_uri(&resolved.pubkey))
        }
        None => Err(AlterNetError::ManifestInvalid(format!("bilinmeyen isim: {name}"))),
    }
}

// ═══════════════════════════════════════════════
// Zone Delegation Çözümleme — alter://alice/blog
// ═══════════════════════════════════════════════

/// Bir zone deposu: parent_pubkey_hex/subname → imzalı `ZoneDelegation`.
///
/// Üretimde `discovery.rs` bu kayıtları DHT `/alternet/zone/{parent}/{subname}`
/// anahtarlarından doldurur; testlerde elle eklenir.
///
/// Manifesto IV: Delegasyon imzalıdır — bir anahtar yalnızca **kendi** alt-isimlerini
/// devredebilir; sahte delegasyon imza doğrulamasında reddedilir.
#[derive(Debug, Default)]
pub struct ZoneStore {
    /// (parent_pubkey_hex, subname) → child_pubkey
    delegations: HashMap<(String, String), Vec<u8>>,
}

impl ZoneStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// İmzalı bir delegasyonu doğrulayıp ekle.
    ///
    /// `verify_zone_delegation` parent imzasını kontrol eder — sahte kayıt reddedilir.
    pub fn add(&mut self, zd: &ZoneDelegation) -> Result<()> {
        verify_zone_delegation(zd).map_err(AlterNetError::Crypto)?;
        let parent_hex = data_encoding::HEXLOWER.encode(&zd.parent_pubkey);
        self.delegations
            .insert((parent_hex, zd.subname.clone()), zd.child_pubkey.clone());
        Ok(())
    }

    /// `parent_pubkey` altındaki `subname` alt-ismini çöz.
    pub fn resolve(&self, parent_pubkey: &[u8], subname: &str) -> Option<Vec<u8>> {
        let parent_hex = data_encoding::HEXLOWER.encode(parent_pubkey);
        self.delegations
            .get(&(parent_hex, subname.to_string()))
            .cloned()
    }
}

/// `alter://alice/blog` biçimindeki tam adresi çöz.
///
/// 1. İlk bileşen (`alice`) `resolver` ile pubkey'e çözülür (petname veya self-cert).
/// 2. Sonraki her bileşen (`blog`, `blog/posts` ...) `zones` üzerinden zincirleme
///    zone delegasyonu olarak çözülür — her adım imzalıdır.
///
/// Sonuç: en alt child anahtarının `alter://<pubkey>` adresi + kalan içerik alt-yolu.
///
/// Manifesto IV: Hiçbir global otorite yok — her delegasyon yayıncının imzasıyla bağlı.
pub fn resolve_full_uri(
    uri: &str,
    resolver: &dyn NameResolver,
    zones: &ZoneStore,
) -> Result<String> {
    let stripped = uri
        .strip_prefix("alter://")
        .ok_or_else(|| AlterNetError::ManifestInvalid("alter:// öneki gerekli".into()))?;

    let mut parts = stripped.split('/');
    let root = parts
        .next()
        .ok_or_else(|| AlterNetError::ManifestInvalid("boş adres".into()))?;

    // İlk bileşeni çöz: önce isim çözücü (petname/WoT), bulunamazsa self-cert base32.
    // (base32 alfabesi 'alice' gibi kısa isimleri de decode edebildiğinden sıra önemli.)
    let mut current_pubkey = match resolver.resolve(root)? {
        Some(r) => r.pubkey,
        None => alter_uri_to_pubkey(&format!("alter://{root}"))?,
    };

    // Sonraki her bileşeni zone delegasyonu olarak çöz
    for sub in parts {
        if sub.is_empty() {
            continue;
        }
        match zones.resolve(&current_pubkey, sub) {
            Some(child) => current_pubkey = child,
            None => {
                // Delegasyon yok → kalan kısım içerik alt-yoludur, çözümü durdur.
                break;
            }
        }
    }

    Ok(crate::identity::pubkey_to_alter_uri(&current_pubkey))
}

// ═══════════════════════════════════════════════
// DHT Anahtarları & İmzalı Petname Listesi (WoT yayını için)
// ═══════════════════════════════════════════════

/// Bir yayıncının petname listesinin DHT anahtarı.
pub fn petnames_dht_key(pubkey_hex: &str) -> String {
    format!("/alternet/petnames/{pubkey_hex}")
}

/// Bir zone delegasyonunun DHT anahtarı.
pub fn zone_dht_key(parent_pubkey_hex: &str, subname: &str) -> String {
    format!("/alternet/zone/{parent_pubkey_hex}/{subname}")
}

/// Bir yayıncının atadığı petname'lerin imzalı listesi (DHT yayını).
///
/// Manifesto IV: Başkaları bu listeyi WoT çözümünde kullanabilir; imza yayıncının
/// gerçekten bu isimleri atadığını kanıtlar. İmzasız liste reddedilir (Manifesto VII).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPetnameList {
    pub author: Vec<u8>,
    pub entries: Vec<PetnameEntry>,
    pub signature: Vec<u8>,
}

fn petname_list_signing_bytes(author: &[u8], entries: &[PetnameEntry]) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(&(author, entries), &mut buf).unwrap_or_default();
    buf
}

/// Yerel petname'lerini imzalı listeye dönüştür (DHT'ye yayınlamak için).
pub fn sign_petname_list(
    keypair: &libp2p::identity::Keypair,
    entries: Vec<PetnameEntry>,
) -> Result<SignedPetnameList> {
    let author = keypair.public().encode_protobuf();
    let signature = keypair
        .sign(&petname_list_signing_bytes(&author, &entries))
        .map_err(|e| AlterNetError::Crypto(format!("imzalama: {e:?}")))?;
    Ok(SignedPetnameList { author, entries, signature })
}

/// İmzalı petname listesini doğrula ve girdileri döndür.
pub fn verify_petname_list(list: &SignedPetnameList) -> Result<Vec<PetnameEntry>> {
    let pk = libp2p::identity::PublicKey::try_decode_protobuf(&list.author)
        .map_err(|e| AlterNetError::PublicKeyDecode(e.to_string()))?;
    if !pk.verify(
        &petname_list_signing_bytes(&list.author, &list.entries),
        &list.signature,
    ) {
        return Err(AlterNetError::SignatureInvalid);
    }
    Ok(list.entries.clone())
}

// ═══════════════════════════════════════════════
// Yardımcı
// ═══════════════════════════════════════════════

/// Petname geçerliliğini kontrol et.
/// Yalnızca küçük harf, rakam, tire ve alt çizgiye izin verilir.
fn validate_petname(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(AlterNetError::ManifestInvalid(
            "petname 1-64 karakter olmalı".into(),
        ));
    }
    if !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_') {
        return Err(AlterNetError::ManifestInvalid(
            "petname yalnızca a-z, 0-9, -, _ içerebilir".into(),
        ));
    }
    Ok(())
}

// ═══════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{pubkey_to_alter_uri, pubkey_to_hex};
    use libp2p::identity::Keypair;

    fn dummy_pubkey() -> (Keypair, Vec<u8>, String) {
        let kp = Keypair::generate_ed25519();
        let bytes = kp.public().encode_protobuf();
        let hex = pubkey_to_hex(&bytes);
        (kp, bytes, hex)
    }

    #[test]
    fn petname_assign_and_resolve() {
        let mut store = PetnameStore::in_memory();
        let (_, pubkey, _) = dummy_pubkey();

        store.assign("alice", &pubkey, Some("test".into())).unwrap();
        let result = store.resolve("alice").unwrap().unwrap();
        assert_eq!(result.pubkey, pubkey);
        assert_eq!(result.source, "direct");
    }

    #[test]
    fn petname_remove() {
        let mut store = PetnameStore::in_memory();
        let (_, pubkey, _) = dummy_pubkey();

        store.assign("bob", &pubkey, None).unwrap();
        assert!(store.resolve("bob").unwrap().is_some());
        store.remove("bob").unwrap();
        assert!(store.resolve("bob").unwrap().is_none());
    }

    #[test]
    fn petname_list() {
        let mut store = PetnameStore::in_memory();
        let (_, pubkey, _) = dummy_pubkey();
        let (_, pubkey2, _) = dummy_pubkey();

        store.assign("alice", &pubkey, None).unwrap();
        store.assign("bob", &pubkey2, None).unwrap();
        assert_eq!(store.list().len(), 2);
    }

    #[test]
    fn self_certifying_uri_resolves() {
        let store = PetnameStore::in_memory();
        let (kp, _, _) = dummy_pubkey();
        let pubkey_bytes = kp.public().encode_protobuf();
        let uri = pubkey_to_alter_uri(&pubkey_bytes);

        let result = store.resolve(&uri).unwrap().unwrap();
        assert_eq!(result.pubkey, pubkey_bytes);
        assert_eq!(result.source, "self-cert");
    }

    #[test]
    fn alter_uri_with_subpath_resolves() {
        let store = PetnameStore::in_memory();
        let (kp, _, _) = dummy_pubkey();
        let pubkey_bytes = kp.public().encode_protobuf();
        let base_uri = pubkey_to_alter_uri(&pubkey_bytes);
        let uri_with_path = format!("{}/blog/post1", base_uri);

        let (base, subpath) = parse_alter_uri(&uri_with_path).unwrap();
        assert_eq!(base, base_uri);
        assert_eq!(subpath, Some("blog/post1".into()));

        // Base URI'yi çözümle
        let result = store.resolve(&base).unwrap().unwrap();
        assert_eq!(result.pubkey, pubkey_bytes);
    }

    #[test]
    fn invalid_petname_rejected() {
        let mut store = PetnameStore::in_memory();
        let (_, pubkey, _) = dummy_pubkey();

        // Boş isim
        assert!(store.assign("", &pubkey, None).is_err());
        // Büyük harf
        assert!(store.assign("Alice", &pubkey, None).is_err());
        // Özel karakter
        assert!(store.assign("ali ce", &pubkey, None).is_err());
        // Geçerli
        assert!(store.assign("alice-123", &pubkey, None).is_ok());
    }

    #[test]
    fn unknown_name_returns_none() {
        let store = PetnameStore::in_memory();
        assert!(store.resolve("unknown").unwrap().is_none());
    }

    #[test]
    fn parse_alter_uri_no_subpath() {
        let (kp, _, _) = dummy_pubkey();
        let uri = pubkey_to_alter_uri(&kp.public().encode_protobuf());
        let (base, subpath) = parse_alter_uri(&uri).unwrap();
        assert_eq!(base, uri);
        assert_eq!(subpath, None);
    }

    #[test]
    fn parse_alter_uri_invalid() {
        assert!(parse_alter_uri("http://example.com").is_err());
        assert!(parse_alter_uri("").is_err());
    }

    #[tokio::test]
    async fn petname_store_persist_and_reload() {
        let tmp = tempfile::tempdir().unwrap();
        let (_, pubkey, _) = dummy_pubkey();

        {
            let mut store = PetnameStore::open(tmp.path()).await.unwrap();
            store.assign("alice", &pubkey, Some("test".into())).unwrap();
            store.save().await.unwrap();
        }

        {
            let store = PetnameStore::open(tmp.path()).await.unwrap();
            let result = store.resolve("alice").unwrap().unwrap();
            assert_eq!(result.pubkey, pubkey);
        }
    }

    // ─── Web of Trust çözümleme ───

    #[test]
    fn wot_resolves_via_trusted_peer() {
        // Yerel kullanıcı (me) → Alice'e güvenir. Alice "haberler" → Target yayınlamış.
        let (_, me_pk, me_hex) = dummy_pubkey();
        let (_, alice_pk, _) = dummy_pubkey();
        let (_, target_pk, _) = dummy_pubkey();

        let mut wot = WotResolver::new(PetnameStore::in_memory(), me_hex);
        // me → alice (güvenilir)
        wot.add_trust(&me_pk, &alice_pk, 8);
        // Alice'in yayınladığı petname: "haberler" → target
        wot.ingest_peer_petnames(
            &alice_pk,
            vec![PetnameEntry {
                name: "haberler".into(),
                pubkey_hex: pubkey_to_hex(&target_pk),
                note: None,
            }],
        );

        let resolved = wot.resolve_wot("haberler").unwrap();
        assert_eq!(resolved.pubkey, target_pk);
        assert_eq!(resolved.source, "wot:1");
    }

    #[test]
    fn wot_two_hop_resolution() {
        // me → alice → bob; bob "blog" → target yayınlamış (2 hop)
        let (_, me_pk, me_hex) = dummy_pubkey();
        let (_, alice_pk, _) = dummy_pubkey();
        let (_, bob_pk, _) = dummy_pubkey();
        let (_, target_pk, _) = dummy_pubkey();

        let mut wot = WotResolver::new(PetnameStore::in_memory(), me_hex);
        wot.add_trust(&me_pk, &alice_pk, 5);
        wot.add_trust(&alice_pk, &bob_pk, 5);
        wot.ingest_peer_petnames(
            &bob_pk,
            vec![PetnameEntry {
                name: "blog".into(),
                pubkey_hex: pubkey_to_hex(&target_pk),
                note: None,
            }],
        );

        let resolved = wot.resolve_wot("blog").unwrap();
        assert_eq!(resolved.pubkey, target_pk);
        assert_eq!(resolved.source, "wot:2");
    }

    #[test]
    fn wot_ignores_distrusted_peer() {
        // me → mallory (score 0 = güvensiz). Mallory'nin petname'i çözülmemeli.
        let (_, me_pk, me_hex) = dummy_pubkey();
        let (_, mallory_pk, _) = dummy_pubkey();
        let (_, target_pk, _) = dummy_pubkey();

        let mut wot = WotResolver::new(PetnameStore::in_memory(), me_hex);
        wot.add_trust(&me_pk, &mallory_pk, 0); // güvensiz
        wot.ingest_peer_petnames(
            &mallory_pk,
            vec![PetnameEntry {
                name: "fake".into(),
                pubkey_hex: pubkey_to_hex(&target_pk),
                note: None,
            }],
        );

        assert!(wot.resolve_wot("fake").is_none(), "güvensiz peer çözülmemeli");
    }

    #[test]
    fn wot_respects_max_depth() {
        // 4-hop zincir ama max_depth=3 → en derindeki isim çözülmemeli
        let (_, me_pk, me_hex) = dummy_pubkey();
        let (_, p1, _) = dummy_pubkey();
        let (_, p2, _) = dummy_pubkey();
        let (_, p3, _) = dummy_pubkey();
        let (_, p4, _) = dummy_pubkey();
        let (_, target, _) = dummy_pubkey();

        let mut wot = WotResolver::new(PetnameStore::in_memory(), me_hex);
        wot.add_trust(&me_pk, &p1, 5);
        wot.add_trust(&p1, &p2, 5);
        wot.add_trust(&p2, &p3, 5);
        wot.add_trust(&p3, &p4, 5);
        // p4 (4. hop) bir isim yayınlar — max_depth=3 olduğundan ulaşılamaz
        wot.ingest_peer_petnames(
            &p4,
            vec![PetnameEntry { name: "deep".into(), pubkey_hex: pubkey_to_hex(&target), note: None }],
        );

        assert!(wot.resolve_wot("deep").is_none(), "max_depth dışı isim çözülmemeli");
    }

    #[test]
    fn wot_add_trust_edge_verifies_signature() {
        use crate::governance::create_trust_edge;
        let (kp, from_pk, from_hex) = dummy_pubkey();
        let (_, target_pk, _) = dummy_pubkey();

        let edge = create_trust_edge(&kp, "peer-b".into(), 7, "tanıdık".into()).unwrap();
        let mut wot = WotResolver::new(PetnameStore::in_memory(), from_hex);
        // İmzalı kenar kabul edilir; hedef pubkey ayrıca verilir
        assert!(wot.add_trust_edge(&edge, &target_pk).is_ok());

        wot.ingest_peer_petnames(
            &target_pk,
            vec![PetnameEntry { name: "site".into(), pubkey_hex: pubkey_to_hex(&from_pk), note: None }],
        );
        // from → target güveni kuruldu; target'ın "site" yayını çözülür
        assert!(wot.resolve_wot("site").is_some());
    }

    // ─── Zone delegation (alter://alice/blog) ───

    #[test]
    fn zone_delegation_resolves() {
        use crate::governance::create_zone_delegation;
        let alice = Keypair::generate_ed25519();
        let alice_pk = alice.public().encode_protobuf();
        let bob = Keypair::generate_ed25519();
        let bob_pk = bob.public().encode_protobuf();

        // Alice "blog" alt-ismini Bob'a devreder (imzalı)
        let zd = create_zone_delegation(&alice, "blog".into(), bob_pk.clone()).unwrap();
        let mut zones = ZoneStore::new();
        zones.add(&zd).unwrap();

        let resolved = zones.resolve(&alice_pk, "blog").unwrap();
        assert_eq!(resolved, bob_pk);
    }

    #[test]
    fn zone_store_rejects_tampered_delegation() {
        use crate::governance::create_zone_delegation;
        let alice = Keypair::generate_ed25519();
        let bob = Keypair::generate_ed25519();
        let mut zd =
            create_zone_delegation(&alice, "blog".into(), bob.public().encode_protobuf()).unwrap();
        zd.subname = "hacked".into(); // imzayı boz
        let mut zones = ZoneStore::new();
        assert!(zones.add(&zd).is_err(), "bozulmuş delegasyon reddedilmeli");
    }

    #[test]
    fn signed_petname_list_round_trip() {
        let kp = Keypair::generate_ed25519();
        let (_, target, _) = dummy_pubkey();
        let entries = vec![PetnameEntry {
            name: "alice".into(),
            pubkey_hex: pubkey_to_hex(&target),
            note: None,
        }];
        let signed = sign_petname_list(&kp, entries.clone()).unwrap();
        let verified = verify_petname_list(&signed).unwrap();
        assert_eq!(verified, entries);
    }

    #[test]
    fn signed_petname_list_tamper_rejected() {
        let kp = Keypair::generate_ed25519();
        let (_, target, _) = dummy_pubkey();
        let mut signed = sign_petname_list(
            &kp,
            vec![PetnameEntry { name: "alice".into(), pubkey_hex: pubkey_to_hex(&target), note: None }],
        )
        .unwrap();
        signed.entries[0].name = "mallory".into(); // imzayı boz
        assert!(verify_petname_list(&signed).is_err());
    }

    #[test]
    fn full_uri_petname_plus_zone() {
        use crate::governance::create_zone_delegation;
        // alice (petname) → Alice key; Alice "blog" → Bob key
        let alice = Keypair::generate_ed25519();
        let alice_pk = alice.public().encode_protobuf();
        let bob = Keypair::generate_ed25519();
        let bob_pk = bob.public().encode_protobuf();

        let mut store = PetnameStore::in_memory();
        store.assign("alice", &alice_pk, None).unwrap();

        let mut zones = ZoneStore::new();
        let zd = create_zone_delegation(&alice, "blog".into(), bob_pk.clone()).unwrap();
        zones.add(&zd).unwrap();

        // alter://alice/blog → Bob'un adresi
        let resolved = resolve_full_uri("alter://alice/blog", &store, &zones).unwrap();
        assert_eq!(resolved, pubkey_to_alter_uri(&bob_pk));
    }
}

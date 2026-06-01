//! # AlterNet Discovery — Keşif & Akışlar (L8)
//!
//! Web of Trust tabanlı içerik keşfi: güvenilen anahtarlara abonelik, etiket indeksi,
//! ve gizliliği koruyan arama.
//!
//! **Manifesto IV:** Keşif merkezi bir dizine değil, kullanıcının güven grafiğine dayanır.
//! **Manifesto V:** Sorgu sızıntısı bir tehdittir — arama sorguları onion yolu üzerinden
//! yapılabilir (`routing::PrivacyLevel::Onion`).
//!
//! ## Bileşenler
//! - **WoT Feed:** Güvenilen yazarların en güncel manifestlerini topla (abonelik).
//! - **Etiket İndeksi:** DHT'de `tag → [author]` kayıtları (imzalı).
//! - **Arama:** Etiketle yazar bul; manifestleri çek + doğrula.
//!
//! ## Tehdit Modeli
//! - **Korunan:** Sahte etiket kaydı (her kayıt yazar tarafından Ed25519 imzalı)
//! - **Sınır:** Etiket indeksi DHT'de herkese açık (kim neyi etiketledi görünür)
//! - **Sınır:** Arama sorgusu, Onion modu kapalıysa sorgulanan peer'a sızar

use crate::error::{AlterNetError, Result};
use crate::governance::{now_ms, sign_bytes, verify_bytes, decode_public_key};
use libp2p::identity::Keypair;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════
// İmzalı Etiket Beyanı
// ═══════════════════════════════════════════════

/// Bir yazarın bir siteyi belirli etiketlerle işaretlediğine dair imzalı beyan.
///
/// DHT'de `/alternet/tag/{tag}` altında saklanır. Manifesto VII: imzasız beyan geçersiz.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TagClaim {
    /// İşaretleyen yazarın public key'i (protobuf encoded).
    pub author: Vec<u8>,
    /// Etiket (ör. "blog", "haber", "forum").
    pub tag: String,
    /// İşaretlenen yazarın `alter://` adresi (genelde kendisi).
    pub target_author: Vec<u8>,
    /// Beyan zamanı (unix epoch ms).
    pub claimed_at: i64,
    /// Ed25519 imza.
    pub signature: Vec<u8>,
}

/// İmza için byte dizisi (signature alanı boş).
fn tag_claim_signing_bytes(claim: &TagClaim) -> Vec<u8> {
    let mut c = claim.clone();
    c.signature.clear();
    let mut buf = Vec::new();
    ciborium::into_writer(&c, &mut buf).unwrap_or_default();
    buf
}

/// İmzalı etiket beyanı oluştur.
pub fn create_tag_claim(
    keypair: &Keypair,
    tag: String,
    target_author: Vec<u8>,
) -> Result<TagClaim> {
    let mut claim = TagClaim {
        author: keypair.public().encode_protobuf(),
        tag,
        target_author,
        claimed_at: now_ms(),
        signature: Vec::new(),
    };
    claim.signature = sign_bytes(keypair, &tag_claim_signing_bytes(&claim))
        .map_err(AlterNetError::Crypto)?;
    Ok(claim)
}

/// Etiket beyanının imzasını doğrula.
pub fn verify_tag_claim(claim: &TagClaim) -> Result<()> {
    let pk = decode_public_key(&claim.author).map_err(AlterNetError::Crypto)?;
    if !verify_bytes(&pk, &tag_claim_signing_bytes(claim), &claim.signature) {
        return Err(AlterNetError::SignatureInvalid);
    }
    Ok(())
}

/// Bir etiketin DHT kayıt anahtarı.
pub fn tag_dht_key(tag: &str) -> String {
    format!("/alternet/tag/{}", tag.trim().to_lowercase())
}

// ═══════════════════════════════════════════════
// Yerel Etiket İndeksi
// ═══════════════════════════════════════════════

/// Yerel olarak bilinen etiket → yazarlar indeksi.
///
/// Üretimde DHT'den `get_record(tag_dht_key(tag))` ile beslenir; her beyan
/// `verify_tag_claim` ile doğrulanır. Sahte beyanlar reddedilir.
#[derive(Debug, Default)]
pub struct TagIndex {
    /// tag → doğrulanmış TagClaim listesi
    by_tag: HashMap<String, Vec<TagClaim>>,
}

impl TagIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Doğrulanmış bir etiket beyanını indekse ekle.
    ///
    /// İmza geçersizse reddedilir (Manifesto VII).
    pub fn add(&mut self, claim: TagClaim) -> Result<()> {
        verify_tag_claim(&claim)?;
        let tag = claim.tag.trim().to_lowercase();
        let entries = self.by_tag.entry(tag).or_default();
        // Aynı yazar+hedef tekrarını önle
        if !entries.iter().any(|c| c.author == claim.author && c.target_author == claim.target_author) {
            entries.push(claim);
        }
        Ok(())
    }

    /// Bir etiketle işaretlenmiş hedef yazarları döndür.
    pub fn authors_for_tag(&self, tag: &str) -> Vec<Vec<u8>> {
        let tag = tag.trim().to_lowercase();
        self.by_tag
            .get(&tag)
            .map(|v| v.iter().map(|c| c.target_author.clone()).collect())
            .unwrap_or_default()
    }

    /// Bilinen tüm etiketler.
    pub fn tags(&self) -> Vec<String> {
        self.by_tag.keys().cloned().collect()
    }
}

// ═══════════════════════════════════════════════
// WoT Feed — Abonelik
// ═══════════════════════════════════════════════

/// Güvenilen yazarlara abonelik akışı.
///
/// Manifesto IV: kullanıcı kime abone olacağına kendi karar verir — merkezi feed yok.
/// Her abone yazarın en güncel manifest'i periyodik olarak toplanır (üretimde
/// `network::NodeHandle::get_manifest` + `publish::verify_manifest`).
#[derive(Debug, Default)]
pub struct WotFeed {
    /// Abone olunan yazarların public key'leri.
    subscriptions: Vec<Vec<u8>>,
}

impl WotFeed {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bir yazara abone ol.
    pub fn subscribe(&mut self, author_pubkey: Vec<u8>) {
        if !self.subscriptions.contains(&author_pubkey) {
            self.subscriptions.push(author_pubkey);
        }
    }

    /// Aboneliği kaldır.
    pub fn unsubscribe(&mut self, author_pubkey: &[u8]) {
        self.subscriptions.retain(|s| s != author_pubkey);
    }

    /// Abone olunan yazarların listesi.
    pub fn subscriptions(&self) -> &[Vec<u8>] {
        &self.subscriptions
    }

    pub fn is_subscribed(&self, author_pubkey: &[u8]) -> bool {
        self.subscriptions.iter().any(|s| s == author_pubkey)
    }
}

// ═══════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_claim_sign_and_verify() {
        let kp = Keypair::generate_ed25519();
        let target = Keypair::generate_ed25519().public().encode_protobuf();
        let claim = create_tag_claim(&kp, "blog".into(), target).unwrap();
        assert!(verify_tag_claim(&claim).is_ok());
    }

    #[test]
    fn tag_claim_tamper_rejected() {
        let kp = Keypair::generate_ed25519();
        let target = Keypair::generate_ed25519().public().encode_protobuf();
        let mut claim = create_tag_claim(&kp, "blog".into(), target).unwrap();
        claim.tag = "hacked".into();
        assert!(verify_tag_claim(&claim).is_err());
    }

    #[test]
    fn tag_index_add_and_query() {
        let kp = Keypair::generate_ed25519();
        let target_kp = Keypair::generate_ed25519();
        let target = target_kp.public().encode_protobuf();
        let claim = create_tag_claim(&kp, "haber".into(), target.clone()).unwrap();

        let mut index = TagIndex::new();
        index.add(claim).unwrap();

        let authors = index.authors_for_tag("haber");
        assert_eq!(authors.len(), 1);
        assert_eq!(authors[0], target);
        assert!(index.tags().contains(&"haber".to_string()));
    }

    #[test]
    fn tag_index_rejects_forged_claim() {
        let kp = Keypair::generate_ed25519();
        let target = Keypair::generate_ed25519().public().encode_protobuf();
        let mut claim = create_tag_claim(&kp, "blog".into(), target).unwrap();
        claim.signature = vec![0u8; 64]; // sahte imza
        let mut index = TagIndex::new();
        assert!(index.add(claim).is_err());
    }

    #[test]
    fn tag_index_dedups() {
        let kp = Keypair::generate_ed25519();
        let target = Keypair::generate_ed25519().public().encode_protobuf();
        let mut index = TagIndex::new();
        index.add(create_tag_claim(&kp, "x".into(), target.clone()).unwrap()).unwrap();
        index.add(create_tag_claim(&kp, "x".into(), target.clone()).unwrap()).unwrap();
        assert_eq!(index.authors_for_tag("x").len(), 1, "aynı yazar+hedef tekrar etmemeli");
    }

    #[test]
    fn wot_feed_subscribe_unsubscribe() {
        let author = Keypair::generate_ed25519().public().encode_protobuf();
        let mut feed = WotFeed::new();
        feed.subscribe(author.clone());
        assert!(feed.is_subscribed(&author));
        assert_eq!(feed.subscriptions().len(), 1);

        // Tekrar abone → tekrarlanmaz
        feed.subscribe(author.clone());
        assert_eq!(feed.subscriptions().len(), 1);

        feed.unsubscribe(&author);
        assert!(!feed.is_subscribed(&author));
    }

    #[test]
    fn tag_dht_key_normalizes() {
        assert_eq!(tag_dht_key("  Blog "), "/alternet/tag/blog");
        assert_eq!(tag_dht_key("HABER"), "/alternet/tag/haber");
    }
}

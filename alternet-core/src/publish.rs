//! # AlterNet AlterSites — İmzalı Append-Only Site Yayınlama (L5)
//!
//! Ed25519 imzalı manifest ile değişebilir, sansüre dayanıklı site yayınlama.
//!
//! **Manifesto VII:** "Kod söz verir" — imzasız manifest oluşturulamaz.
//! Her manifest yayıncının Ed25519 anahtarıyla imzalanır.
//!
//! **Manifesto I:** Yazar merkezi bir sunucu olmadan yayınlar; doğrulama
//! bir otoriteye değil, matematiğe dayanır.
//!
//! ## Tehdit Modeli
//! - **Korunan:** Sahte manifest (Ed25519 imza doğrulaması)
//! - **Korunan:** Replay/rollback saldırısı (monoton artan sequence numarası)
//! - **Sınır:** İlk yayıncı ifşası — manifest DHT'ye kaydedilirken IP görünebilir
//!   (Faz 4'te Tor ile azaltılır)

use crate::error::{AlterNetError, Result};
use crate::types::{Cid, Manifest, ManifestMeta, SignedProviderAnnouncement};
use libp2p::identity::{Keypair, PublicKey};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// İmza için byte dizisi üret: manifest imzasız, CBOR encode edilmiş.
///
/// İmza alanı boş ayarlanır, geri kalan her şey CBOR olarak seri hale getirilir.
/// Deterministik encoding imza doğrulamasının güvenilirliğini garanti eder.
pub fn manifest_signing_bytes(manifest: &Manifest) -> Result<Vec<u8>> {
    let mut m = manifest.clone();
    m.signature.clear();
    let mut buf = Vec::new();
    ciborium::into_writer(&m, &mut buf)
        .map_err(|e| AlterNetError::CborEncode(e.to_string()))?;
    Ok(buf)
}

/// Yeni imzalı manifest oluştur.
///
/// Manifesto VII: "Kod söz verir" — imzasız manifest döndürme kodu yoktur.
pub fn create_manifest(
    root_cid: Cid,
    keypair: &Keypair,
    sequence: u64,
    metadata: ManifestMeta,
) -> Result<Manifest> {
    let mut manifest = Manifest {
        version: 1,
        author: keypair.public().encode_protobuf(),
        sequence,
        root_cid,
        created_at: unix_now(),
        metadata,
        signature: Vec::new(),
    };

    let signing_bytes = manifest_signing_bytes(&manifest)?;
    manifest.signature = keypair
        .sign(&signing_bytes)
        .map_err(|e| AlterNetError::Crypto(format!("imzalama başarısız: {e:?}")))?;

    Ok(manifest)
}

/// Manifest imzasını ve yapısını doğrula.
///
/// Başarısız olursa `AlterNetError::SignatureInvalid` veya `AlterNetError::ManifestInvalid`.
pub fn verify_manifest(manifest: &Manifest) -> Result<()> {
    if manifest.version != 1 {
        return Err(AlterNetError::ManifestInvalid(format!(
            "desteklenmeyen versiyon: {}",
            manifest.version
        )));
    }
    if manifest.author.is_empty() {
        return Err(AlterNetError::ManifestInvalid("boş author alanı".into()));
    }
    if manifest.signature.is_empty() {
        return Err(AlterNetError::ManifestInvalid("imza eksik".into()));
    }

    let public_key = PublicKey::try_decode_protobuf(&manifest.author)
        .map_err(|e| AlterNetError::PublicKeyDecode(e.to_string()))?;

    let signing_bytes = manifest_signing_bytes(manifest)?;

    if !public_key.verify(&signing_bytes, &manifest.signature) {
        return Err(AlterNetError::SignatureInvalid);
    }

    Ok(())
}

/// Manifest'i CBOR olarak seri hale getir (DHT kaydı için).
pub fn serialize_manifest(manifest: &Manifest) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(manifest, &mut buf)
        .map_err(|e| AlterNetError::CborEncode(e.to_string()))?;
    Ok(buf)
}

/// CBOR'dan manifest deserialize et.
pub fn deserialize_manifest(data: &[u8]) -> Result<Manifest> {
    ciborium::from_reader(data)
        .map_err(|e| AlterNetError::CborDecode(e.to_string()))
}

// ═══════════════════════════════════════════════
// Provider Announcement — DHT Provider İmzalama
// ═══════════════════════════════════════════════

/// DHT'de provider imza kaydı için string anahtar.
///
/// `put_dht` / `get_dht` ile kullanılır; BLAKE3 ile RecordKey'e dönüştürülür.
pub fn provider_sig_dht_key(cid_hex: &str) -> String {
    format!("provider_sig/{cid_hex}")
}

/// Yeni imzalı provider duyurusu oluştur.
///
/// `timestamp` çoğunlukla `unix_now()` olacak; testlerde sabit değer geçilebilir.
///
/// İmzalanan mesaj: `author_pubkey || content_cid_bytes || announced_at_be64`
pub fn sign_provider_announcement(
    keypair: &Keypair,
    cid: &str,
    timestamp: u64,
) -> Result<SignedProviderAnnouncement> {
    let author_pubkey = keypair.public().encode_protobuf();
    let mut ann = SignedProviderAnnouncement {
        author_pubkey,
        content_cid: cid.to_string(),
        announced_at: timestamp,
        signature: Vec::new(),
    };
    let msg = ann.signing_bytes();
    ann.signature = keypair
        .sign(&msg)
        .map_err(|e| AlterNetError::Crypto(format!("provider imzalama başarısız: {e:?}")))?;
    Ok(ann)
}

/// Provider duyurusunun imzasını ve yapısını doğrula.
///
/// `false` döndüğünde duyuru atlanmalı ve uyarı loglanmalı.
pub fn verify_provider_announcement(ann: &SignedProviderAnnouncement) -> bool {
    if ann.author_pubkey.is_empty() || ann.content_cid.is_empty() || ann.signature.is_empty() {
        return false;
    }
    let public_key = match PublicKey::try_decode_protobuf(&ann.author_pubkey) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let msg = ann.signing_bytes();
    public_key.verify(&msg, &ann.signature)
}

/// Provider duyurusunu CBOR olarak seri hale getir (DHT PUT değeri).
pub fn serialize_provider_announcement(ann: &SignedProviderAnnouncement) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(ann, &mut buf)
        .map_err(|e| AlterNetError::CborEncode(e.to_string()))?;
    Ok(buf)
}

/// CBOR'dan provider duyurusu deserialize et (DHT GET değerinden).
pub fn deserialize_provider_announcement(data: &[u8]) -> Result<SignedProviderAnnouncement> {
    ciborium::from_reader(data)
        .map_err(|e| AlterNetError::CborDecode(e.to_string()))
}

// ═══════════════════════════════════════════════
// ManifestStore — Replay/Rollback Koruması
// ═══════════════════════════════════════════════

/// Bilinen manifest'lerin yerel append-only log'u.
///
/// Her yayıncı için kabul edilen manifest'lerin **tüm geçmişini** sequence sırasıyla
/// saklar. Yeni bir manifest yalnızca seq > son_seq ise kabul edilir; aksi hâlde
/// replay/rollback saldırısı olarak reddedilir.
///
/// **Manifesto V (AlterSites):** "Yazar başına append-only imzalı log." — site
/// güncellemeleri zincirlenir; eski sürümlere erişilebilir, ama eski sürüm yeni
/// sürümü geçemez.
/// **Manifesto VII:** Rollback koruması devre dışı bırakılamaz.
#[derive(Debug, Default)]
pub struct ManifestStore {
    /// author_pubkey → kabul edilen manifest'lerin sequence-sıralı geçmişi
    history: HashMap<Vec<u8>, Vec<Manifest>>,
}

impl ManifestStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Manifest'i doğrula ve log'a ekle.
    ///
    /// Önce imza doğrulaması (`verify_manifest`) yapılır, ardından sequence
    /// monotonluğu kontrol edilir. Her ikisi de geçerse manifest geçmişe eklenir.
    pub fn accept(&mut self, manifest: &Manifest) -> Result<()> {
        verify_manifest(manifest)?;

        let last_seq = self.last_seq(&manifest.author);
        if manifest.sequence <= last_seq {
            return Err(AlterNetError::ManifestInvalid(format!(
                "replay/rollback: gelen seq={} ≤ bilinen seq={}",
                manifest.sequence, last_seq
            )));
        }

        self.history
            .entry(manifest.author.clone())
            .or_default()
            .push(manifest.clone());
        Ok(())
    }

    /// Belirli bir yayıncı için son bilinen sequence numarasını döndür.
    pub fn last_seq(&self, author: &[u8]) -> u64 {
        self.history
            .get(author)
            .and_then(|h| h.last())
            .map(|m| m.sequence)
            .unwrap_or(0)
    }

    /// Bir yayıncının tüm manifest geçmişi (sequence artan sırada).
    ///
    /// Manifesto V: yayın geçmişi denetlenebilir — sansür/değişiklik kanıtı.
    pub fn history(&self, author: &[u8]) -> &[Manifest] {
        self.history.get(author).map(|h| h.as_slice()).unwrap_or(&[])
    }

    /// Bir yayıncının en güncel (son) manifest'i.
    pub fn latest(&self, author: &[u8]) -> Option<&Manifest> {
        self.history.get(author).and_then(|h| h.last())
    }

    /// Belirli bir sequence numarasındaki manifest'i getir (sürüm gezinme).
    pub fn at_sequence(&self, author: &[u8], sequence: u64) -> Option<&Manifest> {
        self.history
            .get(author)
            .and_then(|h| h.iter().find(|m| m.sequence == sequence))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cid() -> Cid {
        Cid::from_data(b"test content for manifest")
    }

    #[test]
    fn create_and_verify_manifest() {
        let keypair = Keypair::generate_ed25519();
        let manifest = create_manifest(test_cid(), &keypair, 1, ManifestMeta::default()).unwrap();
        assert!(verify_manifest(&manifest).is_ok());
    }

    #[test]
    fn tampered_sequence_rejected() {
        let keypair = Keypair::generate_ed25519();
        let mut manifest =
            create_manifest(test_cid(), &keypair, 1, ManifestMeta::default()).unwrap();
        manifest.sequence = 999;
        assert!(verify_manifest(&manifest).is_err());
    }

    #[test]
    fn tampered_root_cid_rejected() {
        let keypair = Keypair::generate_ed25519();
        let mut manifest =
            create_manifest(test_cid(), &keypair, 1, ManifestMeta::default()).unwrap();
        manifest.root_cid = Cid::from_data(b"different content");
        assert!(verify_manifest(&manifest).is_err());
    }

    #[test]
    fn tampered_signature_rejected() {
        let keypair = Keypair::generate_ed25519();
        let mut manifest =
            create_manifest(test_cid(), &keypair, 1, ManifestMeta::default()).unwrap();
        if let Some(b) = manifest.signature.first_mut() {
            *b ^= 0xFF;
        }
        assert!(verify_manifest(&manifest).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();
        let mut manifest =
            create_manifest(test_cid(), &keypair1, 1, ManifestMeta::default()).unwrap();
        manifest.author = keypair2.public().encode_protobuf();
        assert!(verify_manifest(&manifest).is_err());
    }

    #[test]
    fn serialize_deserialize_round_trip() {
        let keypair = Keypair::generate_ed25519();
        let manifest = create_manifest(
            test_cid(),
            &keypair,
            42,
            ManifestMeta {
                title: Some("Test Site".into()),
                description: Some("AlterNet test".into()),
                mime_type: Some("text/html".into()),
                tags: vec!["test".into()],
                encrypted: false,
            },
        )
        .unwrap();
        let bytes = serialize_manifest(&manifest).unwrap();
        let manifest2 = deserialize_manifest(&bytes).unwrap();
        assert!(verify_manifest(&manifest2).is_ok());
        assert_eq!(manifest.sequence, manifest2.sequence);
        assert_eq!(manifest.metadata.title, manifest2.metadata.title);
    }

    #[test]
    fn missing_signature_rejected() {
        let keypair = Keypair::generate_ed25519();
        let mut manifest =
            create_manifest(test_cid(), &keypair, 1, ManifestMeta::default()).unwrap();
        manifest.signature.clear();
        assert!(verify_manifest(&manifest).is_err());
    }

    #[test]
    fn manifest_store_accepts_increasing_seq() {
        let keypair = Keypair::generate_ed25519();
        let mut store = ManifestStore::new();

        let m1 = create_manifest(test_cid(), &keypair, 1, ManifestMeta::default()).unwrap();
        assert!(store.accept(&m1).is_ok());
        assert_eq!(store.last_seq(&m1.author), 1);

        let m2 = create_manifest(test_cid(), &keypair, 2, ManifestMeta::default()).unwrap();
        assert!(store.accept(&m2).is_ok());
        assert_eq!(store.last_seq(&m2.author), 2);
    }

    #[test]
    fn manifest_store_rejects_replay() {
        let keypair = Keypair::generate_ed25519();
        let mut store = ManifestStore::new();

        let m1 = create_manifest(test_cid(), &keypair, 5, ManifestMeta::default()).unwrap();
        store.accept(&m1).unwrap();

        // Aynı seq → replay → reddedilmeli
        let m_same = create_manifest(test_cid(), &keypair, 5, ManifestMeta::default()).unwrap();
        assert!(store.accept(&m_same).is_err(), "aynı seq replay saldırısı");

        // Daha düşük seq → rollback → reddedilmeli
        let m_old = create_manifest(test_cid(), &keypair, 3, ManifestMeta::default()).unwrap();
        assert!(store.accept(&m_old).is_err(), "düşük seq rollback saldırısı");
    }

    #[test]
    fn manifest_store_rejects_tampered_manifest() {
        let keypair = Keypair::generate_ed25519();
        let mut store = ManifestStore::new();

        let mut manifest =
            create_manifest(test_cid(), &keypair, 1, ManifestMeta::default()).unwrap();
        manifest.sequence = 999; // imzayı bozuyor
        assert!(store.accept(&manifest).is_err(), "bozuk imzalı manifest kabul edilemez");
    }

    #[test]
    fn manifest_store_keeps_full_history() {
        let keypair = Keypair::generate_ed25519();
        let author = keypair.public().encode_protobuf();
        let mut store = ManifestStore::new();

        // Üç sürüm yayınla
        for seq in 1..=3 {
            let m = create_manifest(test_cid(), &keypair, seq, ManifestMeta::default()).unwrap();
            store.accept(&m).unwrap();
        }

        // Geçmiş tüm sürümleri sırayla tutmalı (Manifesto V: append-only log)
        let hist = store.history(&author);
        assert_eq!(hist.len(), 3);
        assert_eq!(hist[0].sequence, 1);
        assert_eq!(hist[2].sequence, 3);

        // Sürüm gezinme
        assert_eq!(store.at_sequence(&author, 2).unwrap().sequence, 2);
        assert!(store.at_sequence(&author, 99).is_none());

        // En güncel
        assert_eq!(store.latest(&author).unwrap().sequence, 3);
    }

    #[test]
    fn manifest_store_empty_history() {
        let store = ManifestStore::new();
        let keypair = Keypair::generate_ed25519();
        let author = keypair.public().encode_protobuf();
        assert!(store.history(&author).is_empty());
        assert!(store.latest(&author).is_none());
        assert_eq!(store.last_seq(&author), 0);
    }

    // ── Provider Announcement Tests ────────────────────────────────────────

    #[test]
    fn sign_and_verify_roundtrip() {
        let keypair = Keypair::generate_ed25519();
        let cid_hex = Cid::from_data(b"provider test content").to_hex();
        let ann = sign_provider_announcement(&keypair, &cid_hex, 1_700_000_000).unwrap();
        assert!(verify_provider_announcement(&ann), "geçerli imza doğrulanmalı");
    }

    #[test]
    fn tampered_sig_rejected() {
        let keypair = Keypair::generate_ed25519();
        let cid_hex = Cid::from_data(b"provider tamper test").to_hex();
        let mut ann = sign_provider_announcement(&keypair, &cid_hex, 1_700_000_001).unwrap();
        // İmzanın ilk byte'ını boz.
        if let Some(b) = ann.signature.first_mut() {
            *b ^= 0xFF;
        }
        assert!(!verify_provider_announcement(&ann), "bozuk imza reddedilmeli");
    }

    #[test]
    fn tampered_cid_rejected() {
        let keypair = Keypair::generate_ed25519();
        let cid_hex = Cid::from_data(b"provider cid tamper").to_hex();
        let mut ann = sign_provider_announcement(&keypair, &cid_hex, 1_700_000_002).unwrap();
        ann.content_cid = Cid::from_data(b"different content").to_hex();
        assert!(!verify_provider_announcement(&ann), "farklı CID ile imza reddedilmeli");
    }

    #[test]
    fn tampered_timestamp_rejected() {
        let keypair = Keypair::generate_ed25519();
        let cid_hex = Cid::from_data(b"provider ts tamper").to_hex();
        let mut ann = sign_provider_announcement(&keypair, &cid_hex, 1_700_000_003).unwrap();
        ann.announced_at += 1;
        assert!(!verify_provider_announcement(&ann), "değiştirilen timestamp ile imza reddedilmeli");
    }

    #[test]
    fn wrong_key_provider_rejected() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();
        let cid_hex = Cid::from_data(b"provider wrong key").to_hex();
        let mut ann = sign_provider_announcement(&keypair1, &cid_hex, 1_700_000_004).unwrap();
        // Farklı key'in pubkey'ini yaz — imza artık eşleşmemeli.
        ann.author_pubkey = keypair2.public().encode_protobuf();
        assert!(!verify_provider_announcement(&ann), "yanlış pubkey ile imza reddedilmeli");
    }

    #[test]
    fn provider_announcement_serialize_deserialize_roundtrip() {
        let keypair = Keypair::generate_ed25519();
        let cid_hex = Cid::from_data(b"provider serde test").to_hex();
        let ann = sign_provider_announcement(&keypair, &cid_hex, 1_700_000_005).unwrap();
        let bytes = serialize_provider_announcement(&ann).unwrap();
        let ann2 = deserialize_provider_announcement(&bytes).unwrap();
        assert_eq!(ann, ann2);
        assert!(verify_provider_announcement(&ann2));
    }

    #[test]
    fn provider_sig_dht_key_format() {
        let cid_hex = "deadbeef";
        assert_eq!(provider_sig_dht_key(cid_hex), "provider_sig/deadbeef");
    }
}

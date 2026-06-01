//! # AlterNet Governance — Web of Trust & İsim Çözümü Altyapısı
//!
//! TrustEdge, imzalama/doğrulama, ve isim çözümü için petname/zone yapıları.
//!
//! **Manifesto IV:** Güven dayatılmaz, inşa edilir. Her kullanıcı kendi güven
//! politikasını belirler. Güven imzalı kriptografik kanıtlarla inşa edilir.
//!
//! ## Tehdit Modeli
//! - **Korunan:** Sahte güven beyanları (Ed25519 imza doğrulaması)
//! - **Korunan:** Güven manipülasyonu (her TrustEdge imzalı + doğrulanabilir)
//! - **Sınır:** Sybil saldırısı ile sahte güven grafiği oluşturulabilir
//!
//! Kaynak: AlterChat governance.rs + AlterNet petname/zone uzantıları.
//! bincode → ciborium dönüşümü uygulanmıştır.

use libp2p::{PeerId, identity};
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════
// TrustEdge — Güven Grafiği Kenarı
// ═══════════════════════════════════════════════

/// İki peer arasındaki güven ilişkisi.
///
/// Manifesto IV: "Güven imzalı kriptografik kanıtlarla inşa edilir."
/// Score: -10 (tam güvensiz) ile +10 (tam güvenilir) arası.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEdge {
    pub from_peer_id: String,
    #[serde(default)]
    pub from_public_key: Vec<u8>,
    pub to_peer_id: String,
    pub score: i32,
    pub reason: String,
    pub issued_at: i64,
    pub signature: Vec<u8>,
}

// ═══════════════════════════════════════════════
// AlterNet Uzantıları — Petname & Zone Delegation
// ═══════════════════════════════════════════════

/// Yerel petname kaydı — kullanıcının bir anahtara atadığı okunabilir isim.
///
/// Manifesto IV: İsimler yereldir. Global namespace yok, squatting yok.
/// İsim çözümü WoT üzerinden yapılır: "güvendiğim kişilerin X dediği anahtar."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PetnameRecord {
    /// Okunabilir isim (ör. "alice", "favori-blog").
    pub name: String,
    /// Hedef public key (protobuf encoded).
    pub target_pubkey: Vec<u8>,
    /// Atayan kişinin public key'i.
    pub assigned_by: Vec<u8>,
    /// Atama zamanı (unix epoch ms).
    pub assigned_at: i64,
}

/// Zone delegasyonu — bir anahtar, alt-isim → anahtar eşlemesini imzalı yayınlar.
///
/// Örnek: Alice `alter://alice/blog` → Bob'un anahtarına delegasyon yapar.
/// Manifesto IV: Delegasyon imzalıdır, güven zinciri doğrulanabilir.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneDelegation {
    /// Delege eden (üst) public key.
    pub parent_pubkey: Vec<u8>,
    /// Alt-isim (ör. "blog").
    pub subname: String,
    /// Hedef public key.
    pub child_pubkey: Vec<u8>,
    /// İmza (parent_pubkey ile).
    pub signature: Vec<u8>,
}

// ═══════════════════════════════════════════════
// Revokasyon
// ═══════════════════════════════════════════════

/// Dağıtık revokasyon duyurusu.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationAnnouncement {
    pub invite_id: String,
    pub room_id: String,
    pub revoked_by: String,
    pub revoked_at: i64,
    pub signature: Vec<u8>,
}

pub const REVOCATION_TOPIC: &str = "_alternet_revocations";

// ═══════════════════════════════════════════════
// İmzalama / Doğrulama Altyapısı
// ═══════════════════════════════════════════════

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

pub fn random_nonce() -> [u8; 16] {
    use aes_gcm::aead::{OsRng, rand_core::RngCore};
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// CBOR canonical signing bytes — imza hariç tüm alanları seri hale getirir.
fn cbor_signing_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).unwrap_or_default();
    buf
}

pub fn trust_edge_signing_bytes(edge: &TrustEdge) -> Vec<u8> {
    let mut clone = edge.clone();
    clone.signature.clear();
    cbor_signing_bytes(&clone)
}

pub fn revocation_signing_bytes(ann: &RevocationAnnouncement) -> Vec<u8> {
    let mut clone = ann.clone();
    clone.signature.clear();
    cbor_signing_bytes(&clone)
}

pub fn zone_delegation_signing_bytes(zd: &ZoneDelegation) -> Vec<u8> {
    let mut clone = zd.clone();
    clone.signature.clear();
    cbor_signing_bytes(&clone)
}

/// Ed25519 imzala.
pub fn sign_bytes(keypair: &identity::Keypair, payload: &[u8]) -> Result<Vec<u8>, String> {
    keypair
        .sign(payload)
        .map_err(|e| format!("sign failed: {e:?}"))
}

/// Ed25519 doğrula.
pub fn verify_bytes(public_key: &identity::PublicKey, payload: &[u8], signature: &[u8]) -> bool {
    public_key.verify(payload, signature)
}

/// Public key decode (protobuf encoded bytes → PublicKey).
pub fn decode_public_key(bytes: &[u8]) -> Result<identity::PublicKey, String> {
    identity::PublicKey::try_decode_protobuf(bytes)
        .map_err(|e| format!("invalid public key: {e:?}"))
}

/// Public key'den PeerId türet.
pub fn public_key_peer_id(public_key: &identity::PublicKey) -> String {
    PeerId::from(public_key.clone()).to_string()
}

// ═══════════════════════════════════════════════
// TrustEdge Oluşturma & Doğrulama
// ═══════════════════════════════════════════════

/// Yeni TrustEdge oluştur (imzalı).
pub fn create_trust_edge(
    keypair: &identity::Keypair,
    to_peer_id: String,
    score: i32,
    reason: String,
) -> Result<TrustEdge, String> {
    let mut edge = TrustEdge {
        from_peer_id: PeerId::from(keypair.public()).to_string(),
        from_public_key: keypair.public().encode_protobuf(),
        to_peer_id,
        score: score.clamp(-10, 10),
        reason,
        issued_at: now_ms(),
        signature: Vec::new(),
    };
    edge.signature = sign_bytes(keypair, &trust_edge_signing_bytes(&edge))?;
    Ok(edge)
}

/// TrustEdge imzasını doğrula.
pub fn verify_trust_edge(edge: &TrustEdge) -> Result<(), String> {
    let public_key = decode_public_key(&edge.from_public_key)?;
    if public_key_peer_id(&public_key) != edge.from_peer_id {
        return Err("trust edge public key does not match source peer id".to_string());
    }
    if !verify_bytes(
        &public_key,
        &trust_edge_signing_bytes(edge),
        edge.signature.as_slice(),
    ) {
        return Err("trust edge signature rejected".to_string());
    }
    Ok(())
}

/// Zone delegasyonu oluştur (imzalı).
pub fn create_zone_delegation(
    keypair: &identity::Keypair,
    subname: String,
    child_pubkey: Vec<u8>,
) -> Result<ZoneDelegation, String> {
    let mut zd = ZoneDelegation {
        parent_pubkey: keypair.public().encode_protobuf(),
        subname,
        child_pubkey,
        signature: Vec::new(),
    };
    zd.signature = sign_bytes(keypair, &zone_delegation_signing_bytes(&zd))?;
    Ok(zd)
}

/// Zone delegasyonu doğrula.
pub fn verify_zone_delegation(zd: &ZoneDelegation) -> Result<(), String> {
    let public_key = decode_public_key(&zd.parent_pubkey)?;
    if !verify_bytes(
        &public_key,
        &zone_delegation_signing_bytes(zd),
        zd.signature.as_slice(),
    ) {
        return Err("zone delegation signature rejected".to_string());
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_edge_signature_rejects_tampering() {
        let keypair = identity::Keypair::generate_ed25519();
        let mut edge =
            create_trust_edge(&keypair, "peer-b".to_string(), 7, "known".to_string()).unwrap();
        assert!(verify_trust_edge(&edge).is_ok());
        edge.score = -7;
        assert!(verify_trust_edge(&edge).is_err());
    }

    #[test]
    fn zone_delegation_round_trip() {
        let parent = identity::Keypair::generate_ed25519();
        let child = identity::Keypair::generate_ed25519();
        let zd = create_zone_delegation(
            &parent,
            "blog".to_string(),
            child.public().encode_protobuf(),
        )
        .unwrap();
        assert!(verify_zone_delegation(&zd).is_ok());
    }

    #[test]
    fn zone_delegation_rejects_tampering() {
        let parent = identity::Keypair::generate_ed25519();
        let child = identity::Keypair::generate_ed25519();
        let mut zd = create_zone_delegation(
            &parent,
            "blog".to_string(),
            child.public().encode_protobuf(),
        )
        .unwrap();
        zd.subname = "hacked".to_string();
        assert!(verify_zone_delegation(&zd).is_err());
    }
}

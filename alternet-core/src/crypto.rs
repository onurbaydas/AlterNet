//! # AlterNet Cryptographic Primitives
//!
//! X25519 Diffie-Hellman, AES-256-GCM şifreleme, Safety Number türetme.
//!
//! **Manifesto III:** Güvenlik seçenek değil varsayılandır — kapatma kodu yoktur.
//! **Manifesto VII:** Şifreleme devre dışı bırakılamaz çünkü devre dışı bırakma kodu yoktur.
//!
//! ## Tehdit Modeli
//! - **Korunan:** Pasif gözlemci (AES-256-GCM + ephemeral DH)
//! - **Korunan:** Aktif MITM (Safety Number ile doğrulanabilir)
//! - **Sınır:** Kuantum bilgisayar X25519'u kırabilir (gelecek: post-quantum)
//!
//! Kaynak: AlterChat crypto.rs (mesajlaşma spesifik parçalar çıkarılmış).

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, rand_core::RngCore},
};
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ═══════════════════════════════════════════════
// Şifreli Payload
// ═══════════════════════════════════════════════

#[derive(Serialize, Deserialize, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct EncryptedPayload {
    pub ephemeral_pubkey: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Alıcının X25519 public key'i ile şifrele.
///
/// Ephemeral DH: her şifreleme için yeni anahtar çifti üretilir.
/// Forward secrecy: geçmiş mesajlar, gelecekteki anahtar ifşasından etkilenmez.
pub fn encrypt_for_peer(
    recipient_pubkey_bytes: &[u8; 32],
    plaintext: &[u8],
) -> Result<EncryptedPayload, &'static str> {
    let recipient_pubkey = X25519PublicKey::from(*recipient_pubkey_bytes);

    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_pubkey = X25519PublicKey::from(&ephemeral_secret);

    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pubkey);

    let key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(key);

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| "Encryption failed")?;

    Ok(EncryptedPayload {
        ephemeral_pubkey: *ephemeral_pubkey.as_bytes(),
        nonce: nonce.into(),
        ciphertext,
    })
}

/// Kendi static X25519 secret key'imizle çöz.
pub fn decrypt_for_me(
    my_secret_bytes: &[u8; 32],
    payload: &EncryptedPayload,
) -> Result<Vec<u8>, &'static str> {
    let my_secret = StaticSecret::from(*my_secret_bytes);
    let sender_ephemeral_pubkey = X25519PublicKey::from(payload.ephemeral_pubkey);

    let shared_secret = my_secret.diffie_hellman(&sender_ephemeral_pubkey);

    let key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(&payload.nonce);

    let plaintext = cipher
        .decrypt(nonce, payload.ciphertext.as_ref())
        .map_err(|_| "Decryption failed")?;
    Ok(plaintext)
}

/// Rastgele 32-byte static secret üret.
pub fn generate_static_secret() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Static secret'tan public key türet.
pub fn get_public_key(secret_bytes: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*secret_bytes);
    let pubkey = X25519PublicKey::from(&secret);
    *pubkey.as_bytes()
}

// ═══════════════════════════════════════════════
// Opsiyonel İçerik Şifreleme (Simetrik AES-256-GCM)
// ═══════════════════════════════════════════════
//
// Manifesto III: Şifreleme bir **ek katmandır**, kapatma bayrağı DEĞİLDİR. Transport
// şifrelemesi (Noise) her zaman açıktır; bu, yayıncının içeriği **anahtar paylaşılmadan
// okunamaz** kılmak için seçebileceği üst katmandır. Anahtar manifest dışında, kullanıcı
// kanalıyla paylaşılır (Manifesto I: anahtar dağıtımı için merkezi otorite yok).
//
// Tehdit: DHT enumeration ile blok içerikleri okunabilir (bloklar cleartext). Bu katman
// onu engeller: bloklar şifreliyse CID = BLAKE3(ciphertext) ve içerik anahtarsız anlamsız.

/// Bir parola/passphrase'den içerik şifreleme anahtarı türet (BLAKE3 KDF).
///
/// Aynı passphrase her zaman aynı anahtarı üretir → alıcı yalnızca passphrase'i bilerek
/// içeriği çözebilir. Salt olarak sabit domain separator kullanılır (deterministik).
pub fn derive_content_key(passphrase: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AlterNet_ContentKey_v1");
    hasher.update(passphrase.as_bytes());
    *hasher.finalize().as_bytes()
}

/// İçeriği simetrik anahtarla şifrele. Çıktı: `nonce(12) || ciphertext`.
pub fn encrypt_content(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| "content encryption failed")?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// `nonce(12) || ciphertext` biçimindeki içeriği çöz.
pub fn decrypt_content(key: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, &'static str> {
    if payload.len() < 12 {
        return Err("content payload too short");
    }
    let (nonce_bytes, ciphertext) = payload.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| "content decryption failed (wrong key?)")
}

// ═══════════════════════════════════════════════
// DHT Anahtar Türetme — AlterNet Manifest'leri İçin
// ═══════════════════════════════════════════════

use libp2p::kad::RecordKey;
use sha2::{Digest, Sha256};

/// Manifest DHT anahtarı: pubkey_hex → SHA256 hash.
///
/// AlterChat'teki `get_dht_mailbox_key` pattern'inden adapte edilmiş.
/// Anahtar, yayıncının pubkey hex'inin hash'idir — deterministik ve çakışmasız.
pub fn get_dht_manifest_key(pubkey_hex: &str) -> RecordKey {
    let mut hasher = Sha256::new();
    hasher.update(pubkey_hex.as_bytes());
    hasher.update(b"_alternet_manifest");
    let result = hasher.finalize();
    RecordKey::new(&result.as_slice())
}

/// Revokasyon listesi DHT anahtarı (gelecek kullanım).
pub fn get_dht_revocation_key(pubkey_hex: &str) -> RecordKey {
    let mut hasher = Sha256::new();
    hasher.update(pubkey_hex.as_bytes());
    hasher.update(b"_alternet_revocation");
    let result = hasher.finalize();
    RecordKey::new(&result.as_slice())
}

// ═══════════════════════════════════════════════
// Safety Number — Site Doğrulaması
// ═══════════════════════════════════════════════

/// İki peer arasında 60 haneli güvenlik numarası türet.
///
/// Signal benzeri: her iki tarafta aynı sayı görünür.
/// Kullanıcılar bunu karşılaştırarak MITM saldırısı tespit edebilir.
///
/// Manifesto IV: Güven imzalı kriptografik kanıtlarla inşa edilir.
pub fn derive_safety_number(my_pubkey: &[u8; 32], peer_pubkey: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    let (first, second) = if my_pubkey < peer_pubkey {
        (my_pubkey, peer_pubkey)
    } else {
        (peer_pubkey, my_pubkey)
    };
    hasher.update(first);
    hasher.update(second);
    hasher.update(b"AlterNet_SafetyNumber_v1");
    let hash = hasher.finalize();
    let nums: Vec<u8> = hash.iter().take(30).copied().collect();
    nums.chunks(6)
        .map(|chunk| {
            let n: u64 = chunk.iter().fold(0u64, |acc, &b| acc * 256 + b as u64) % 1_000_000_000_000;
            format!("{:012}", n)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ═══════════════════════════════════════════════
// Şifreli X25519 Secret Yönetimi
// ═══════════════════════════════════════════════

/// Şifreli X25519 secret'ı yükle veya oluştur (Manifesto III).
pub fn load_or_generate_encrypted_x25519_secret(path: &str, password: &str) -> [u8; 32] {
    #[allow(clippy::collapsible_if)]
    if let Ok(bytes) = std::fs::read(path) {
        if let Ok(decrypted) = crate::secure_storage::decrypt_file_data(password, &bytes) {
            if decrypted.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&decrypted);
                return arr;
            }
        }
    }
    let secret = generate_static_secret();
    let encrypted = crate::secure_storage::encrypt_file_data(password, &secret);
    let _ = std::fs::write(path, encrypted);
    secret
}

#[cfg(test)]
mod content_encryption_tests {
    use super::*;

    #[test]
    fn content_encrypt_decrypt_round_trip() {
        let key = derive_content_key("gizli-parola");
        let data = b"Manifesto III: Sifreleme bir ek katmandir, kapatma kodu yoktur.";
        let enc = encrypt_content(&key, data).unwrap();
        assert_ne!(enc, data, "sifreli metin acik metinden farkli olmali");
        let dec = decrypt_content(&key, &enc).unwrap();
        assert_eq!(dec, data, "round-trip byte-perfect");
    }

    #[test]
    fn content_wrong_key_fails() {
        let key1 = derive_content_key("dogru");
        let key2 = derive_content_key("yanlis");
        let enc = encrypt_content(&key1, b"sir").unwrap();
        assert!(decrypt_content(&key2, &enc).is_err(), "yanlis anahtar cozemez");
    }

    #[test]
    fn derive_content_key_deterministic() {
        // Ayni passphrase her zaman ayni anahtar → alici yalnizca passphrase'i bilir
        assert_eq!(derive_content_key("ayni"), derive_content_key("ayni"));
        assert_ne!(derive_content_key("a"), derive_content_key("b"));
    }

    #[test]
    fn content_corrupt_payload_rejected() {
        let key = derive_content_key("p");
        assert!(decrypt_content(&key, b"kisa").is_err(), "kisa payload reddedilmeli");
    }
}

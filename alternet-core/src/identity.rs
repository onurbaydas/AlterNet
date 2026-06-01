//! # AlterNet Identity — Egemen Kimlik
//!
//! Ed25519 anahtar çifti = kullanıcının egemen kimliği.
//! Public key = adres. Hesap yok, kayıt yok, izin yok.
//!
//! **Manifesto I:** Hiçbir sunucu, şirket veya devlet otorite sahibi değildir.
//! **Manifesto VII:** Kimlik kriptografik olarak garanti edilir — başlıkla, marka adıyla değil.
//!
//! ## Tehdit Modeli
//! - **Korunan:** Kimlik sahteciliği (Ed25519 imza doğrulaması ile)
//! - **Korunan:** Anahtar hırsızlığı (Argon2 + AES-256-GCM ile şifrelenmiş depolama)
//! - **Sınır:** Anahtar kaybı geri alınamaz — merkezi sıfırlama mekanizması yok (tasarım gereği)
//!
//! Kaynak: AlterChat identity.rs + AlterNet base32 uzantıları.

use crate::secure_storage::{decrypt_file_data, encrypt_file_data};
use libp2p::identity::Keypair;
use std::fs;
use std::path::Path;

/// Mevcut keypair'i yükle veya yeni oluştur (şifresiz).
///
/// `:memory:` path'i geçilirse dosya oluşturmaz (testler için).
pub fn load_or_generate_keypair<P: AsRef<Path>>(
    path: P,
) -> Result<Keypair, Box<dyn std::error::Error>> {
    let path_ref = path.as_ref();
    if path_ref.to_string_lossy() == ":memory:" {
        return Ok(Keypair::generate_ed25519());
    }
    if path_ref.exists() {
        let bytes = fs::read(path_ref)?;
        let keypair = Keypair::from_protobuf_encoding(&bytes)
            .map_err(|e| format!("Failed to parse keypair: {}", e))?;
        Ok(keypair)
    } else {
        let keypair = Keypair::generate_ed25519();
        // Üst dizini oluştur
        if let Some(parent) = path_ref.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(
            path_ref,
            keypair
                .to_protobuf_encoding()
                .map_err(|e| format!("Failed to encode keypair: {:?}", e))?,
        )?;
        Ok(keypair)
    }
}

/// Mevcut keypair'i yükle veya yeni oluştur (şifreli — Manifesto III).
///
/// Anahtar Argon2 + AES-256-GCM ile şifrelenir.
/// Şifreleme kapatılamaz — kapatma kodu yoktur (Manifesto VII).
pub fn load_or_generate_encrypted_keypair<P: AsRef<Path>>(
    path: P,
    password: &str,
) -> Result<Keypair, Box<dyn std::error::Error>> {
    let path_ref = path.as_ref();
    if path_ref.to_string_lossy() == ":memory:" {
        return Ok(Keypair::generate_ed25519());
    }
    if path_ref.exists() {
        let bytes = fs::read(path_ref)?;

        let decrypted = decrypt_file_data(password, &bytes)
            .map_err(|e| format!("Key decryption failed: {}", e))?;

        let keypair = Keypair::from_protobuf_encoding(&decrypted)
            .map_err(|e| format!("Failed to parse keypair: {}", e))?;
        Ok(keypair)
    } else {
        let keypair = Keypair::generate_ed25519();
        let encoded = keypair
            .to_protobuf_encoding()
            .map_err(|e| format!("Failed to encode keypair: {:?}", e))?;

        let encrypted = encrypt_file_data(password, &encoded);
        // Üst dizini oluştur
        if let Some(parent) = path_ref.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path_ref, encrypted)?;
        Ok(keypair)
    }
}

/// Birleşik kimlik yükleyici — parola varsa şifreli, yoksa düz depolama.
///
/// **Manifesto III/V:** Atıl veri şifreli olmalıdır. Parola verildiğinde anahtar
/// Argon2 + AES-256-GCM ile şifrelenir. Parolasız mod yalnızca gözetimsiz daemon
/// kolaylığı içindir ve çağıran tarafça uyarılmalıdır (kapatma kodu değil — tercih).
///
/// `:memory:` → kalıcı olmayan (testler).
pub fn load_identity<P: AsRef<Path>>(
    path: P,
    password: Option<&str>,
) -> Result<Keypair, Box<dyn std::error::Error>> {
    match password {
        Some(pw) if !pw.is_empty() => load_or_generate_encrypted_keypair(path, pw),
        _ => load_or_generate_keypair(path),
    }
}

// ═══════════════════════════════════════════════
// AlterNet Uzantıları — alter:// URI dönüşümleri
// ═══════════════════════════════════════════════

/// Public key'i `alter://` URI'ye dönüştür.
///
/// Format: `alter://<BASE32_NOPAD(pubkey_bytes)>`
/// Tor .onion mantığı: adres kriptografik olarak anahtara bağlıdır.
/// İsim sahteciliği matematiksel olarak imkânsızdır (Manifesto VII).
pub fn pubkey_to_alter_uri(pubkey_bytes: &[u8]) -> String {
    let encoded = data_encoding::BASE32_NOPAD.encode(pubkey_bytes);
    format!("alter://{}", encoded.to_lowercase())
}

/// `alter://` URI'den public key bytes'ı çıkar.
///
/// `alter://` prefix'i strip edilir, base32 decode yapılır.
pub fn alter_uri_to_pubkey(uri: &str) -> crate::error::Result<Vec<u8>> {
    let stripped = uri
        .strip_prefix("alter://")
        .ok_or_else(|| crate::error::AlterNetError::InvalidUri(uri.to_string()))?;

    // Subpath varsa ayır: alter://KEY/subpath
    let key_part = stripped.split('/').next().unwrap_or(stripped);

    data_encoding::BASE32_NOPAD
        .decode(key_part.to_uppercase().as_bytes())
        .map_err(|e| {
            crate::error::AlterNetError::InvalidUri(format!("base32 decode failed: {e}"))
        })
}

/// Public key bytes'ı hex string'e dönüştür (DHT key'leri için).
pub fn pubkey_to_hex(pubkey_bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(pubkey_bytes)
}

/// `alter://` URI'den subpath bileşenini çıkar (varsa).
///
/// Örnek: `alter://ABC123/blog/post1` → `Some("blog/post1")`
pub fn alter_uri_subpath(uri: &str) -> Option<String> {
    let stripped = uri.strip_prefix("alter://")?;
    let slash_pos = stripped.find('/')?;
    let subpath = &stripped[slash_pos + 1..];
    if subpath.is_empty() {
        None
    } else {
        Some(subpath.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_memory_mode() {
        let kp = load_or_generate_keypair(":memory:").unwrap();
        assert!(kp.public().to_peer_id().to_string().len() > 0);
    }

    #[test]
    fn alter_uri_round_trip() {
        let kp = Keypair::generate_ed25519();
        let pubkey_bytes = kp.public().encode_protobuf();
        let uri = pubkey_to_alter_uri(&pubkey_bytes);
        assert!(uri.starts_with("alter://"));

        let decoded = alter_uri_to_pubkey(&uri).unwrap();
        assert_eq!(pubkey_bytes, decoded);
    }

    #[test]
    fn alter_uri_subpath_extraction() {
        assert_eq!(
            alter_uri_subpath("alter://abc123/blog/post1"),
            Some("blog/post1".to_string())
        );
        assert_eq!(alter_uri_subpath("alter://abc123"), None);
        assert_eq!(alter_uri_subpath("alter://abc123/"), None);
    }

    #[test]
    fn invalid_uri_rejected() {
        assert!(alter_uri_to_pubkey("http://example.com").is_err());
        assert!(alter_uri_to_pubkey("alternet://abc").is_err());
    }
}

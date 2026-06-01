//! # AlterNet AlterExchange — Blok Değişim Protokolü (L4)
//!
//! Bitswap benzeri peer-to-peer blok değişimi. İstemciler istedikleri blokları
//! CID ile ister; diğer node'lar sahip olduklarını veya olmadıklarını bildirir.
//!
//! **Manifesto III:** Her blok teslim alındığında CID = BLAKE3(veri) doğrulanır.
//! **Manifesto I:** Merkezi aracı yok — doğrudan peer-to-peer blok transferi.
//!
//! ## Tehdit Modeli
//! - **Korunan:** Sahte blok teslimatı (alıcı her zaman CID = BLAKE3(veri) doğrular)
//! - **Sınır:** Hangi CID'lerin istendiği bilgisi sorgulayan peer'a sızar (sorgu sızıntısı)

use crate::onion::OnionPacket;
use crate::types::{Cid, Manifest};
use serde::{Deserialize, Serialize};

/// Blok isteği — bir peer'dan blok veya manifest iste.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExchangeRequest {
    /// PoW kimlik doğrulama isteği (SybilGuard için).
    /// Ağ bağlantısı kurulduğunda peer kimliğini doğrulamak için gönderilir.
    PoWHandshake {
        token: crate::pow::PoWToken,
    },
    /// Tek bir blok iste (CID ile).
    ///
    /// `pad`: trafik analizi karşıtı dolgu. `PrivacyLevel::Padded+` aktifken istek
    /// 512B katına yuvarlanır; pasif gözlemci istek boyutundan içerik tahmin edemez.
    /// Manifesto V: metadata sızdırılmaz. Boş bırakılırsa (Clear modu) dolgu yok.
    WantBlock {
        cid: Cid,
        #[serde(default)]
        pad: Vec<u8>,
    },
    /// Çoklu blok iste (Pipelining / Want-list)
    WantBlocks {
        cids: Vec<Cid>,
        #[serde(default)]
        pad: Vec<u8>,
    },
    /// Hangi bloklara sahip olduğunu sor.
    HaveQuery { cids: Vec<Cid> },
    /// Bir yayıncının en güncel manifestini iste.
    WantManifest { author_pubkey: Vec<u8> },
    /// Onion sarılı istek — relay düğümü tarafından iletilir.
    ///
    /// Alıcı düğüm bir onion katmanı soyar ve iç isteği yanıtlar
    /// ya da sonraki hop'a iletir. Bu sayede gönderenin kimliği gizlenir.
    ///
    /// Manifesto V: "Mahremiyet varsayılandır."
    OnionForward {
        packet: OnionPacket,
        /// X25519 public key (yanıtı şifrelemek için — yanıt yolunda).
        reply_pubkey: Vec<u8>,
    },
}

/// Blok yanıtı.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExchangeResponse {
    /// PoW kimlik doğrulama yanıtı.
    PoWHandshakeAck { accepted: bool },
    /// İstenen blok verisi.
    Block { cid: Cid, data: Vec<u8> },
    /// Çoklu blok verisi (Pipelined).
    Blocks { blocks: Vec<(Cid, Vec<u8>)> },
    /// Blok bu node'da yok.
    DontHave { cid: Cid },
    /// Sahip olunan CID'lerin listesi (HaveQuery yanıtı).
    HaveList { cids: Vec<Cid> },
    /// Manifest verisi.
    Manifest { manifest: Box<Manifest> },
    /// Manifest bu node'da yok.
    ManifestNotFound,
    /// Onion relay yanıtı — şifrelenmiş blok verisi.
    OnionResult { encrypted_data: Vec<u8> },
}

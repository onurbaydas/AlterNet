//! # AlterNet Routing — Onion Yönlendirme & Trafik Gizliliği (L6)
//!
//! Sansüre karşı direnci ve kullanıcı gizliliğini **teknik zorunluluk** olarak uygular.
//! Ağ gözlemcisi ne içeriğe ne gönderene ulaşabilir.
//!
//! **Manifesto V:** Mahremiyet saklanmak için değil, **insan olduğun için** hakkındır.
//! **Manifesto III:** Güvenlik seçenek değil, varsayılandır.
//!
//! ## Gizlilik Seviyeleri
//!
//! | Seviye  | Koruma                                               | Maliyet       |
//! |---------|------------------------------------------------------|---------------|
//! | `Clear` | Yok — test veya güvenli yerel ağ için               | En hızlı      |
//! | `Padded`| 512B pad + chaff + time-blind (trafik analizi engel) | Düşük         |
//! | `Onion` | Sphinx 3-hop onion (gönderen kimliği gizli)          | Orta          |
//! | `Tor`   | Tor network — IP ve trafik tamamen gizli             | En yüksek     |
//!
//! ## Tehdit Modeli
//! - **Korunan (Padded+):** ISP trafik analizi — sabit 512B paketler, chaff, rastgele gecikme
//! - **Korunan (Onion+):** DHT enumeration — CID sorgularını kim sorduğu bilinmez
//! - **Korunan (Tor):** IP ifşası — gönderenin IP'si ağdan gizlidir
//! - **Sınır:** Global pasif gözlemci zamanlama korelasyonu yapabilir (Onion seviyesinde)
//! - **Sınır:** Tor exit node aktif MITM yapabilir (libp2p Noise bunu önler)
//! - **Sınır:** `Tor` modu çalışan `tor` daemon gerektirir (Faz 4 — dışsal bağımlılık)

use crate::error::{AlterNetError, Result};
use crate::exchange::ExchangeRequest;
use crate::network::NodeHandle;
use crate::onion::{OnionPacket, wrap_onion};
use crate::traffic::{generate_chaff_payload, pad_message, time_blind_delay_ms, unpad_message};
use crate::types::Cid;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;

// ═══════════════════════════════════════════════
// Gizlilik Konfigürasyonu
// ═══════════════════════════════════════════════

/// Bağlantı gizlilik seviyesi.
///
/// Her seviye bir öncekini içerir: Onion ⊃ Padded ⊃ Clear.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PrivacyLevel {
    /// Ham bağlantı — test veya güvenli yerel ağ için.
    #[default]
    Clear,
    /// 512B padding + chaff + time-blind gecikme.
    /// Pasif ISP gözlemcisine karşı temel koruma.
    Padded,
    /// Sphinx onion routing (3 hop varsayılan).
    /// Gönderenin kimliği DHT'den ve relay düğümlerinden gizlidir.
    Onion { hops: u8 },
    /// Tor network üzerinden tüm bağlantılar.
    /// IP adresi tamamen gizlidir. `tor` daemon gerektirir.
    Tor,
}

impl PrivacyLevel {
    /// Seviyenin bir üst seviye kadar koruma sağlayıp sağlamadığını kontrol et.
    pub fn at_least_padded(&self) -> bool {
        !matches!(self, PrivacyLevel::Clear)
    }
}

/// Routing katmanı yapılandırması.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// Gizlilik seviyesi.
    pub level: PrivacyLevel,
    /// Periyodik chaff (sahte) trafik. Pasif gözlemcinin ne zaman gerçek
    /// istek yapıldığını anlamasını zorlaştırır.
    pub chaff_enabled: bool,
    /// Zaman-kör gecikme: 0-5000ms rastgele gecikme.
    /// ISP zamanlama korelasyonunu engeller.
    pub time_blind_enabled: bool,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            level: PrivacyLevel::Padded,
            chaff_enabled: true,
            time_blind_enabled: true,
        }
    }
}

// ═══════════════════════════════════════════════
// Relay Düğümü
// ═══════════════════════════════════════════════

/// Onion route'da bir relay düğümü.
///
/// Her düğüm sadece bir önceki ve sonraki hop'u bilir.
#[derive(Debug, Clone)]
pub struct RelayNode {
    /// libp2p peer kimliği (bağlantı için).
    pub peer_id: PeerId,
    /// X25519 public key (onion şifreleme için).
    pub x25519_pubkey: [u8; 32],
}

/// Onion route: relay düğümleri dizisi.
/// Son eleman hedef peer'dır (bloğu sağlayan kişi).
pub type OnionRoute = Vec<RelayNode>;

// ═══════════════════════════════════════════════
// RoutingLayer
// ═══════════════════════════════════════════════

/// Gizlilik katmanı: her ağ isteğine privacy dönüşümleri uygular.
///
/// Manifesto III: "Güvenlik açılıp kapatılan bir özellik değildir;
/// çünkü kapatma kodu yoktur."
pub struct RoutingLayer {
    pub config: PrivacyConfig,
}

impl RoutingLayer {
    pub fn new(config: PrivacyConfig) -> Self {
        Self { config }
    }

    /// Varsayılan (Padded + chaff + time-blind).
    pub fn default_private() -> Self {
        Self::new(PrivacyConfig::default())
    }

    /// Temiz mod (test için).
    pub fn clear() -> Self {
        Self::new(PrivacyConfig {
            level: PrivacyLevel::Clear,
            chaff_enabled: false,
            time_blind_enabled: false,
        })
    }

    // ─── Trafik Dönüşümleri ────────────────────────

    /// İsteği gizlilik seviyesine göre pad et.
    pub fn pad(&self, data: &[u8]) -> Vec<u8> {
        if self.config.level.at_least_padded() {
            pad_message(data)
        } else {
            data.to_vec()
        }
    }

    /// Padded veriyi çöz.
    pub fn unpad(data: &[u8]) -> Option<Vec<u8>> {
        unpad_message(data)
    }

    /// Zaman-kör gecikme uygula.
    pub async fn delay(&self) {
        if self.config.time_blind_enabled && self.config.level.at_least_padded() {
            let ms = time_blind_delay_ms();
            sleep(Duration::from_millis(ms)).await;
        }
    }

    /// Chaff payload üret (sahte blok boyutunda sahte istek).
    pub fn chaff_payload(&self) -> Vec<u8> {
        generate_chaff_payload()
    }

    // ─── Onion Paket Oluşturma ─────────────────────

    /// Bir blok isteğini Sphinx onion paketi olarak sar.
    ///
    /// `route` deki her düğüm sadece bir önceki ve sonraki hop'u görür.
    /// Son düğüm gerçek blok isteğini görür ve yanıtlar.
    ///
    /// ## Güvenlik garantisi
    /// - Her katman ayrı X25519 ephem key ile şifrelenir.
    /// - Sabit 16KB paket boyutu payload uzunluğunu gizler.
    /// - Geçiş düğümleri içerik CID'ini göremez.
    pub fn build_onion_request(
        &self,
        request: &ExchangeRequest,
        route: &[RelayNode],
    ) -> Result<OnionBlockRequest> {
        if route.is_empty() {
            return Err(AlterNetError::Network("onion route boş olamaz".into()));
        }

        // İsteği CBOR serialize et
        let mut payload = Vec::new();
        ciborium::into_writer(request, &mut payload)
            .map_err(|e| AlterNetError::CborEncode(e.to_string()))?;

        // Onion route: (peer_id_string, x25519_pubkey)
        let sphinx_route: Vec<(String, [u8; 32])> = route
            .iter()
            .map(|n| (n.peer_id.to_string(), n.x25519_pubkey))
            .collect();

        let packet = wrap_onion(&sphinx_route, payload)
            .map_err(|e| AlterNetError::Crypto(e.to_string()))?;

        Ok(OnionBlockRequest {
            packet,
            first_hop: route[0].peer_id,
        })
    }

    // ─── Birleşik Blok Getirme ─────────────────────

    /// Gizlilik seviyesine göre blok getir.
    ///
    /// - `Clear`: doğrudan request_block
    /// - `Padded`: time-blind delay + doğrudan request_block
    /// - `Onion`: onion sarılı request (relay gerektirir)
    /// - `Tor`: tor transport üzerinden (node seviyesinde yapılandırılır)
    pub async fn fetch_block(
        &self,
        node: &NodeHandle,
        peer: PeerId,
        cid: &Cid,
        route: Option<&OnionRoute>,
    ) -> Result<Vec<u8>> {
        // Zaman-kör gecikme
        self.delay().await;

        match &self.config.level {
            PrivacyLevel::Clear | PrivacyLevel::Tor => {
                // Tor: network.rs seviyesinde Tor transport ile yapılandırılmış
                // Burada normal request_block yeterli
                node.request_block(peer, cid).await
            }

            PrivacyLevel::Padded => {
                // Padding zaten network protokolünde uygulanır (exchange.rs)
                // Burada sadece delay yeterli (yukarıda uygulandı)
                node.request_block(peer, cid).await
            }

            PrivacyLevel::Onion { .. } => {
                if let Some(r) = route {
                    // Onion route ile anonim getirme — onion paketi zaten 16KB'a padlenir,
                    // bu yüzden iç istek dolgusu gereksiz.
                    let req = ExchangeRequest::WantBlock { cid: cid.clone(), pad: Vec::new() };
                    let onion_req = self.build_onion_request(&req, r)?;
                    node.request_block_onion(onion_req).await
                } else {
                    // Route yoksa Padded moduna düş
                    tracing::warn!("Onion route belirtilmedi, Padded moduna düşüldü");
                    node.request_block(peer, cid).await
                }
            }
        }
    }
}

/// Onion sarılı blok isteği.
pub struct OnionBlockRequest {
    pub packet: OnionPacket,
    pub first_hop: PeerId,
}

// Not: Periyodik chaff gönderim döngüsü `network.rs::run_chaff_loop` içindedir —
// orada gerçek peer'lara sahte `HaveQuery` yollanır (cmd kanalı erişimi orada).

// ═══════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_unpad_roundtrip() {
        let routing = RoutingLayer::default_private();
        let data = b"Manifesto V: Mahremiyet onurdur";
        let padded = routing.pad(data);
        let unpadded = RoutingLayer::unpad(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn padded_is_larger() {
        let routing = RoutingLayer::default_private();
        let data = b"kisa veri";
        let padded = routing.pad(data);
        assert!(padded.len() >= 512, "padding en az 512 byte olmalı");
    }

    #[test]
    fn clear_mode_no_padding() {
        let routing = RoutingLayer::clear();
        let data = b"kisa veri";
        let result = routing.pad(data);
        assert_eq!(result, data, "clear modda padding uygulanmamalı");
    }

    #[test]
    fn chaff_payload_correct_size() {
        let routing = RoutingLayer::default_private();
        let chaff = routing.chaff_payload();
        assert_eq!(chaff.len(), 512, "chaff BLOCK_SIZE boyutunda olmalı");
    }

    #[test]
    fn privacy_level_hierarchy() {
        assert!(!PrivacyLevel::Clear.at_least_padded());
        assert!(PrivacyLevel::Padded.at_least_padded());
        assert!(PrivacyLevel::Onion { hops: 3 }.at_least_padded());
        assert!(PrivacyLevel::Tor.at_least_padded());
    }

    #[test]
    fn onion_build_requires_nonempty_route() {
        let routing = RoutingLayer::default_private();
        let req = ExchangeRequest::WantBlock {
            cid: crate::types::Cid::from_data(b"test"),
            pad: Vec::new(),
        };
        let result = routing.build_onion_request(&req, &[]);
        assert!(result.is_err(), "boş route hata döndürmeli");
    }

    #[tokio::test]
    async fn delay_in_padded_mode() {
        let routing = RoutingLayer::default_private();
        // Gecikme uygulanabilir olmalı (hata atmamalı)
        // Tam gecikme çok uzun süreceğinden sadece derleme kontrolü
        let timeout = tokio::time::timeout(
            Duration::from_millis(6000), // TIME_BLIND_WINDOW_MS + buffer
            routing.delay(),
        )
        .await;
        assert!(timeout.is_ok(), "delay() süresi içinde tamamlanmalı");
    }

    #[tokio::test]
    async fn no_delay_in_clear_mode() {
        let routing = RoutingLayer::clear();
        // Clear modda delay yoktur → çok hızlı tamamlanmalı
        let timeout = tokio::time::timeout(
            Duration::from_millis(10),
            routing.delay(),
        )
        .await;
        assert!(timeout.is_ok(), "clear modda delay olmamalı");
    }
}

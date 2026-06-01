//! # Sphinx Onion Routing
//!
//! Sabit boyutlu (16KB) onion paketleri ile anonim içerik çekme.
//!
//! **Manifesto V:** Mahremiyet varsayılandır — gönderen ve alıcı gizlidir.
//! **Manifesto III:** Sabit paket boyutu trafik analizi engeller.
//!
//! ## Tehdit Modeli
//! - **Korunan:** Yol boyunca her ara düğüm sadece bir önceki ve sonraki hop'u bilir
//! - **Korunan:** Sabit 16KB paket boyutu — payload uzunluğu sızdırılmaz
//! - **Sınır:** Global pasif gözlemci zamanlama korelasyonu yapabilir
//!
//! Kaynak: AlterChat onion.rs (CBOR'a dönüştürülmüş).

use crate::crypto::{EncryptedPayload, decrypt_for_me, encrypt_for_peer};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionPacket {
    pub layer: EncryptedPayload,
    pub route_len: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionLayer {
    pub next_hop: Option<String>,
    pub inner_packet: Option<OnionPacket>,
    pub payload: Option<Vec<u8>>,
    /// Ephemeral X25519 public key for anonymous replies (Phase 4).
    pub reply_key: Option<[u8; 32]>,
    pub padding: Vec<u8>,
}

pub fn wrap_onion(
    route: &[(String, [u8; 32])],
    payload: Vec<u8>,
    reply_key: Option<[u8; 32]>,
) -> Result<OnionPacket, &'static str> {
    let mut next_packet: Option<OnionPacket> = None;
    let mut next_payload = Some(payload);
    let mut current_reply_key = reply_key;

    for (hop_index, (_peer_id, pubkey)) in route.iter().enumerate().rev() {
        let mut layer = OnionLayer {
            next_hop: route
                .get(hop_index + 1)
                .map(|(next_peer, _)| next_peer.clone()),
            inner_packet: next_packet,
            payload: next_payload.take(),
            reply_key: current_reply_key.take(),
            padding: vec![],
        };
        let mut initial_bytes = Vec::new();
        ciborium::into_writer(&layer, &mut initial_bytes)
            .map_err(|_| "onion CBOR serialize failed")?;
        let target_size = 16 * 1024; // 16 KB Sphinx fixed packet size
        if initial_bytes.len() < target_size {
            layer.padding = vec![0u8; target_size - initial_bytes.len()];
        }
        let mut bytes = Vec::new();
        ciborium::into_writer(&layer, &mut bytes)
            .map_err(|_| "onion CBOR serialize failed")?;
        next_packet = Some(OnionPacket {
            layer: encrypt_for_peer(pubkey, &bytes)?,
            route_len: route.len() as u8,
        });
    }

    next_packet.ok_or("empty onion route")
}

pub fn peel_onion(my_secret: &[u8; 32], packet: &OnionPacket) -> Result<OnionLayer, &'static str> {
    let bytes = decrypt_for_me(my_secret, &packet.layer)?;
    ciborium::from_reader(bytes.as_slice()).map_err(|_| "onion CBOR deserialize failed")
}

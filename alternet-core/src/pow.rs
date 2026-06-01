use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PoWToken {
    pub resource: String,
    pub timestamp: u64,
    pub nonce: u64,
}

impl PoWToken {
    /// Mint a new Proof of Work token for a given resource.
    /// `difficulty` is the number of leading zero bits required in the hash.
    pub fn mint(resource: &str, difficulty: u32) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut nonce = 0u64;
        let resource_bytes = resource.as_bytes();

        loop {
            let mut hasher = Sha256::new();
            hasher.update(resource_bytes);
            hasher.update(timestamp.to_le_bytes());
            hasher.update(nonce.to_le_bytes());
            let hash = hasher.finalize();

            if check_difficulty(&hash, difficulty) {
                return Self {
                    resource: resource.to_string(),
                    timestamp,
                    nonce,
                };
            }
            nonce += 1;
        }
    }

    /// Verify the token.
    /// Returns true if the hash meets the difficulty and the timestamp is within the validity window.
    pub fn verify(&self, expected_resource: &str, difficulty: u32, max_age_seconds: u64) -> bool {
        if self.resource != expected_resource {
            return false;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check if token is too old or from the future
        if now < self.timestamp || now - self.timestamp > max_age_seconds {
            return false;
        }

        let mut hasher = Sha256::new();
        hasher.update(self.resource.as_bytes());
        hasher.update(self.timestamp.to_le_bytes());
        hasher.update(self.nonce.to_le_bytes());
        let hash = hasher.finalize();

        check_difficulty(&hash, difficulty)
    }
}

/// Checks if the first `difficulty` bits of the hash are zero.
fn check_difficulty(hash: &[u8], difficulty: u32) -> bool {
    let mut bits_checked = 0;
    for &byte in hash.iter() {
        if bits_checked >= difficulty {
            return true;
        }
        let remaining_bits = difficulty - bits_checked;
        if remaining_bits >= 8 {
            if byte != 0 {
                return false;
            }
            bits_checked += 8;
        } else {
            let mask = 0xFF << (8 - remaining_bits);
            return (byte & mask) == 0;
        }
    }
    true
}

// ═══════════════════════════════════════════════
// SybilGuard — PoW Tabanlı Peer Kabulü
// ═══════════════════════════════════════════════

use crate::traffic::PowBanList;

/// Sybil saldırısı azaltma: yeni peer'lar bir PoW token sunarak kimlik maliyeti öder.
///
/// **Manifesto II:** Ağ kullanıcılara aittir — sınırsız sahte kimlik üretimi maliyetlidir.
/// **Manifesto I:** Merkezi kayıt yok; maliyet hesaplama ile (PoW) dağıtık uygulanır.
///
/// Geçersiz/eksik token sunan peer'ların başarısızlıkları sayılır; eşik aşılınca
/// peer yerel olarak banlanır (ağ katmanında bağlantı reddedilir).
///
/// ## Sınır
/// Sonsuz kaynaklı saldırgan yine de PoW çözebilir — bu bir maliyet bariyeridir,
/// mutlak engel değil. Ed25519 peer kimliğiyle birlikte kullanılır.
pub struct SybilGuard {
    bans: PowBanList,
    /// Token için gereken zorluk (öncü sıfır bit sayısı).
    pub difficulty: u32,
    /// Token geçerlilik penceresi (saniye).
    pub max_age_secs: u64,
    /// Ban eşiği (bu kadar başarısızlıktan sonra ban).
    pub ban_threshold: u32,
}

impl SybilGuard {
    /// Makul varsayılanlarla yeni guard (difficulty=16, 5dk pencere, 3 başarısızlık).
    pub fn new() -> Self {
        Self {
            bans: PowBanList::new(),
            difficulty: 16,
            max_age_secs: 300,
            ban_threshold: 3,
        }
    }

    pub fn with_difficulty(mut self, difficulty: u32) -> Self {
        self.difficulty = difficulty;
        self
    }

    /// Bir peer'ın PoW token'ını doğrula. Token `peer_id`'yi resource olarak kullanır.
    ///
    /// Başarısızsa peer'ın sayacı artar ve eşik aşılırsa banlanır.
    /// Dönüş: kabul edildi mi (`true`) yoksa reddedildi/banlandı mı (`false`).
    pub fn admit(&mut self, peer_id: &str, token: &PoWToken) -> bool {
        if self.bans.is_banned(peer_id, self.ban_threshold) {
            return false;
        }
        if token.verify(peer_id, self.difficulty, self.max_age_secs) {
            self.bans.reset(peer_id); // başarılı → sayacı temizle
            true
        } else {
            self.bans.record_failure(peer_id, self.ban_threshold);
            false
        }
    }

    /// Bir peer banlı mı?
    pub fn is_banned(&self, peer_id: &str) -> bool {
        self.bans.is_banned(peer_id, self.ban_threshold)
    }

    /// Yerel node'un kendi token'ını üret (bağlanırken sunmak için).
    pub fn mint_token(&self, peer_id: &str) -> PoWToken {
        PoWToken::mint(peer_id, self.difficulty)
    }
}

impl Default for SybilGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_mint_and_verify() {
        let resource = "test_room";
        let difficulty = 12; // Small difficulty for fast test execution

        let token = PoWToken::mint(resource, difficulty);

        assert!(token.verify(resource, difficulty, 60));
        assert!(!token.verify("wrong_room", difficulty, 60)); // Wrong resource
        assert!(!token.verify(resource, difficulty + 8, 60)); // Higher difficulty should fail
    }

    #[test]
    fn sybil_guard_admits_valid_token() {
        let mut guard = SybilGuard::new().with_difficulty(8); // düşük zorluk, hızlı test
        let peer = "12D3KooWPeerExample";
        let token = guard.mint_token(peer);
        assert!(guard.admit(peer, &token), "geçerli token kabul edilmeli");
        assert!(!guard.is_banned(peer));
    }

    #[test]
    fn sybil_guard_bans_after_repeated_failures() {
        let mut guard = SybilGuard::new().with_difficulty(8);
        let peer = "12D3KooWMallory";
        // Geçersiz token (yanlış resource) ile tekrarlanan denemeler
        let bad = PoWToken::mint("baska-resource", 8);
        assert!(!guard.admit(peer, &bad)); // 1. başarısızlık
        assert!(!guard.admit(peer, &bad)); // 2.
        assert!(!guard.admit(peer, &bad)); // 3. → eşik (3) aşıldı
        assert!(guard.is_banned(peer), "eşik aşılınca peer banlanmalı");

        // Banlandıktan sonra geçerli token bile reddedilir
        let good = guard.mint_token(peer);
        assert!(!guard.admit(peer, &good), "banlı peer reddedilmeli");
    }
}

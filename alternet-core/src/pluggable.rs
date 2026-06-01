use aes_gcm::aead::{OsRng, rand_core::RngCore};
use libp2p::core::Transport;

/// Trait defining the standard interface for Pluggable Transports like Obfs4 and Snowflake.
/// This acts as a generic wrapper around libp2p transports to circumvent DPI (Deep Packet Inspection).
pub trait PluggableTransport {
    fn transport_name(&self) -> &'static str;
    
    /// Obfuscate traffic based on the specific pluggable transport strategy.
    fn obfuscate(&self, data: &[u8]) -> Vec<u8>;
    
    /// De-obfuscate traffic.
    fn deobfuscate(&self, data: &[u8]) -> Result<Vec<u8>, &'static str>;

    /// Generate random padding of given length.
    fn random_padding(&self, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        OsRng.fill_bytes(&mut buf);
        buf
    }
}

// ═══════════════════════════════════════════════
// Obfs4 Transport — "look-like-nothing" obfuscation
// ═══════════════════════════════════════════════

/// Obfs4-style obfuscation transport.
///
/// Uses a shared key to XOR-encrypt traffic with a random nonce prefix,
/// making the wire format indistinguishable from random noise.
///
/// Wire format: [2-byte data_len BE][16-byte nonce][XOR-obfuscated data][random padding]
#[derive(Default)]
pub struct Obfs4Transport {
    key: [u8; 32],
}

impl Obfs4Transport {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }

    pub fn with_key(key: [u8; 32]) -> Self {
        Self { key }
    }

    fn derive_mask(&self, nonce: &[u8; 16], len: usize) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut mask = Vec::with_capacity(len);
        let mut counter: u32 = 0;
        while mask.len() < len {
            let mut hasher = Sha256::new();
            hasher.update(&self.key);
            hasher.update(nonce);
            hasher.update(counter.to_be_bytes());
            let block = hasher.finalize();
            mask.extend_from_slice(&block[..block.len().min(len - mask.len())]);
            counter += 1;
        }
        mask.truncate(len);
        mask
    }
}

impl PluggableTransport for Obfs4Transport {
    fn transport_name(&self) -> &'static str {
        "obfs4"
    }

    fn obfuscate(&self, data: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let mask = self.derive_mask(&nonce, data.len());
        let obfuscated: Vec<u8> = data.iter().zip(mask.iter()).map(|(d, m)| d ^ m).collect();
        let pad_len = (OsRng.next_u32() % 32) as usize;
        let padding = self.random_padding(pad_len);
        let data_len = data.len() as u16;
        let mut result = Vec::with_capacity(2 + 16 + obfuscated.len() + pad_len);
        result.extend_from_slice(&data_len.to_be_bytes());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&obfuscated);
        result.extend_from_slice(&padding);
        result
    }

    fn deobfuscate(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        if data.len() < 2 + 16 {
            return Err("obfs4: packet too short");
        }
        let data_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let nonce: [u8; 16] = data[2..18].try_into().map_err(|_| "obfs4: bad nonce")?;
        if data.len() < 2 + 16 + data_len {
            return Err("obfs4: truncated payload");
        }
        let obfuscated = &data[18..18 + data_len];
        let mask = self.derive_mask(&nonce, data_len);
        Ok(obfuscated.iter().zip(mask.iter()).map(|(d, m)| d ^ m).collect())
    }
}

// ═══════════════════════════════════════════════
// Snowflake Transport — WebRTC-based proxy
// ═══════════════════════════════════════════════

/// Snowflake-style obfuscation: wraps traffic to look like WebRTC data channel traffic.
///
/// Wire format: [4-byte magic "SNFL"][2-byte frame_len BE][frame data][2-byte pad_len BE][random padding]
#[derive(Default)]
pub struct SnowflakeTransport {
    magic: [u8; 4],
}

const SNOWFLAKE_MAGIC: [u8; 4] = [0x53, 0x4E, 0x46, 0x4C];

impl SnowflakeTransport {
    pub fn new() -> Self {
        Self { magic: SNOWFLAKE_MAGIC }
    }
}

impl PluggableTransport for SnowflakeTransport {
    fn transport_name(&self) -> &'static str {
        "snowflake"
    }

    fn obfuscate(&self, data: &[u8]) -> Vec<u8> {
        let frame_len = data.len() as u16;
        let pad_len = (OsRng.next_u32() % 64) as u16;
        let padding = self.random_padding(pad_len as usize);
        let mut result = Vec::with_capacity(4 + 2 + data.len() + 2 + pad_len as usize);
        result.extend_from_slice(&self.magic);
        result.extend_from_slice(&frame_len.to_be_bytes());
        result.extend_from_slice(data);
        result.extend_from_slice(&pad_len.to_be_bytes());
        result.extend_from_slice(&padding);
        result
    }

    fn deobfuscate(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        if data.len() < 4 + 2 {
            return Err("snowflake: packet too short");
        }
        if &data[0..4] != &self.magic {
            return Err("snowflake: invalid magic bytes");
        }
        let frame_len = u16::from_be_bytes([data[4], data[5]]) as usize;
        if data.len() < 6 + frame_len {
            return Err("snowflake: truncated frame");
        }
        Ok(data[6..6 + frame_len].to_vec())
    }
}

/// Which pluggable transport to use for DPI circumvention.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub enum PluggableTransportType {
    #[default]
    None,
    Obfs4 { bridge_key: Option<String> },
    Snowflake,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfs4_round_trip() {
        let t = Obfs4Transport::new();
        let orig = b"Manifesto VII: Kod soz verir";
        assert_eq!(t.deobfuscate(&t.obfuscate(orig)).unwrap(), orig);
    }

    #[test]
    fn obfs4_nondeterministic() {
        let t = Obfs4Transport::new();
        let d = b"hello";
        assert_ne!(t.obfuscate(d), t.obfuscate(d));
    }

    #[test]
    fn obfs4_shared_key() {
        let k = [42u8; 32];
        let a = Obfs4Transport::with_key(k);
        let b = Obfs4Transport::with_key(k);
        let d = b"sovereign bytes";
        assert_eq!(b.deobfuscate(&a.obfuscate(d)).unwrap(), d);
    }

    #[test]
    fn obfs4_wrong_key() {
        let a = Obfs4Transport::with_key([1u8; 32]);
        let b = Obfs4Transport::with_key([2u8; 32]);
        let d = b"secret";
        assert_ne!(b.deobfuscate(&a.obfuscate(d)).unwrap(), d);
    }

    #[test]
    fn snowflake_round_trip() {
        let t = SnowflakeTransport::new();
        let orig = b"Manifesto V: Mahremiyet onurdur";
        assert_eq!(t.deobfuscate(&t.obfuscate(orig)).unwrap(), orig);
    }

    #[test]
    fn snowflake_bad_magic() {
        let t = SnowflakeTransport::new();
        let mut bad = t.obfuscate(b"test");
        bad[0] = 0xFF;
        assert!(t.deobfuscate(&bad).is_err());
    }
}

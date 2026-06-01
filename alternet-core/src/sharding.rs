use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngExt;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Shard {
    pub index: u32,
    pub total_shards: u32,
    pub file_id: String,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

pub struct Sharder;

impl Sharder {
    pub const CHUNK_SIZE: usize = 256 * 1024; // 256 KB

    pub fn split_and_encrypt(file_id: &str, data: &[u8], key: &[u8; 32]) -> Vec<Shard> {
        let cipher = Aes256Gcm::new(key.into());
        let chunks: Vec<&[u8]> = data.chunks(Self::CHUNK_SIZE).collect();
        let total_shards = chunks.len() as u32;

        chunks
            .into_iter()
            .enumerate()
            .map(|(i, chunk)| {
                let mut nonce_bytes = [0u8; 12];
                rand::rng().fill(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);
                
                let ciphertext = cipher.encrypt(nonce, chunk).expect("Encryption failure");

                Shard {
                    index: i as u32,
                    total_shards,
                    file_id: file_id.to_string(),
                    ciphertext,
                    nonce: nonce_bytes.to_vec(),
                }
            })
            .collect()
    }

    pub fn decrypt_and_assemble(shards: &mut [Shard], key: &[u8; 32]) -> Result<Vec<u8>, &'static str> {
        let cipher = Aes256Gcm::new(key.into());
        shards.sort_by_key(|s| s.index);

        let mut output = Vec::new();
        for shard in shards {
            let nonce = Nonce::from_slice(&shard.nonce);
            match cipher.decrypt(nonce, shard.ciphertext.as_ref()) {
                Ok(plain) => output.extend_from_slice(&plain),
                Err(_) => return Err("Decryption failed on a shard"),
            }
        }

        Ok(output)
    }
}

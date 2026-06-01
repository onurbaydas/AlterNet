use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use automerge::{AutoCommit, ObjType, ROOT, ReadDoc, transaction::Transactable};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct CrdtMessage {
    pub peer_id: String,
    pub sender: String,
    pub text: String,
    pub timestamp: i64,
    pub ttl: Option<i64>,
}

pub struct Room {
    pub id: String,
    pub doc: AutoCommit,
    encryption_key: [u8; 32],
}

fn derive_room_key(id: &str, password: Option<&str>) -> [u8; 32] {
    let mut key = [0u8; 32];
    match password {
        Some(pwd) => pbkdf2_hmac::<Sha256>(pwd.as_bytes(), id.as_bytes(), 100_000, &mut key),
        // Parolasız oda: oda adından deterministik anahtar türet.
        // Gizli değil — ağ trafiğini şifreler, içerik güvenliği için şifre gerekir.
        None => pbkdf2_hmac::<Sha256>(b"alterchat-open-room", id.as_bytes(), 1_000, &mut key),
    }
    key
}

impl Room {
    pub fn new(id: String, password: Option<&str>) -> Self {
        let mut doc = AutoCommit::new();
        doc.put_object(ROOT, "messages", ObjType::List).unwrap();

        Room {
            encryption_key: derive_room_key(&id, password),
            id,
            doc,
        }
    }

    pub fn load(id: String, bytes: &[u8], password: Option<&str>) -> Result<Self, String> {
        let encryption_key = derive_room_key(&id, password);

        let room_temp = Room {
            id: id.clone(),
            doc: AutoCommit::new(),
            encryption_key,
        };
        let decrypted = room_temp.decrypt_payload(bytes)?;

        let doc = AutoCommit::load(&decrypted).map_err(|e| e.to_string())?;
        Ok(Room {
            id,
            doc,
            encryption_key,
        })
    }

    fn encrypt_payload(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.encryption_key));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 12 bytes
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| "Encryption failed".to_string())?;
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt_payload(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        if payload.len() < 12 {
            return Err("Payload too short for decryption".to_string());
        }
        let (nonce_bytes, ciphertext) = payload.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.encryption_key));
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "Decryption failed (wrong password?)".to_string())
    }

    pub fn save(&mut self) -> Result<Vec<u8>, String> {
        let bytes = self.doc.save();
        self.encrypt_payload(&bytes)
    }

    pub fn add_message(
        &mut self,
        peer_id: &str,
        sender: &str,
        text: &str,
        ttl: Option<i64>,
    ) -> Result<Vec<u8>, String> {
        let messages_obj = self
            .doc
            .get(ROOT, "messages")
            .map_err(|e| e.to_string())?
            .unwrap()
            .1;

        let msg_idx = self.doc.length(&messages_obj);
        let msg_obj = self
            .doc
            .insert_object(&messages_obj, msg_idx, ObjType::Map)
            .map_err(|e| e.to_string())?;

        self.doc
            .put(&msg_obj, "peer_id", peer_id)
            .map_err(|e| e.to_string())?;
        self.doc
            .put(&msg_obj, "sender", sender)
            .map_err(|e| e.to_string())?;
        self.doc
            .put(&msg_obj, "text", text)
            .map_err(|e| e.to_string())?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        self.doc
            .put(&msg_obj, "timestamp", timestamp)
            .map_err(|e| e.to_string())?;
        if let Some(t) = ttl {
            self.doc
                .put(&msg_obj, "ttl", t)
                .map_err(|e| e.to_string())?;
        }
        self.doc.commit();

        self.save()
    }

    pub fn merge(&mut self, other_bytes: &[u8]) -> Result<(), String> {
        let decrypted = self.decrypt_payload(other_bytes)?;
        let mut other_doc = AutoCommit::load(&decrypted).map_err(|e| e.to_string())?;
        self.doc.merge(&mut other_doc).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_messages(&self) -> Result<Vec<CrdtMessage>, String> {
        let mut result = Vec::new();

        if let Some((_, messages_obj)) =
            self.doc.get(ROOT, "messages").map_err(|e| e.to_string())?
        {
            let len = self.doc.length(&messages_obj);
            for i in 0..len {
                if let Some((_, msg_obj)) =
                    self.doc.get(&messages_obj, i).map_err(|e| e.to_string())?
                {
                    let peer_id = self
                        .doc
                        .get(&msg_obj, "peer_id")
                        .unwrap_or(None)
                        .and_then(|(v, _)| v.to_str().map(|s| s.to_string()))
                        .unwrap_or_default();
                    let sender = self
                        .doc
                        .get(&msg_obj, "sender")
                        .unwrap()
                        .and_then(|(v, _)| v.to_str().map(|s| s.to_string()))
                        .unwrap_or_default();
                    let text = self
                        .doc
                        .get(&msg_obj, "text")
                        .unwrap()
                        .and_then(|(v, _)| v.to_str().map(|s| s.to_string()))
                        .unwrap_or_default();
                    let timestamp = self
                        .doc
                        .get(&msg_obj, "timestamp")
                        .unwrap()
                        .and_then(|(v, _)| v.to_i64())
                        .unwrap_or(0);
                    let ttl = self
                        .doc
                        .get(&msg_obj, "ttl")
                        .unwrap()
                        .and_then(|(v, _)| v.to_i64());

                    let expired = if let Some(t) = ttl {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as i64;
                        (now - timestamp) > (t * 1000)
                    } else {
                        false
                    };

                    if expired {
                        result.push(CrdtMessage {
                            peer_id: peer_id.clone(),
                            sender: sender.clone(),
                            text: "[MESSAGE EXPIRED]".to_string(),
                            timestamp,
                            ttl,
                        });
                    } else {
                        result.push(CrdtMessage {
                            peer_id,
                            sender,
                            text,
                            timestamp,
                            ttl,
                        });
                    }
                }
            }
        }

        Ok(result)
    }
}

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
    Aes256Gcm, Key, Nonce,
};
use argon2::Argon2;
use zeroize::Zeroize;

pub fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    let _ = argon2.hash_password_into(password.as_bytes(), salt, &mut key);
    key
}

pub fn encrypt_file_data(password: &str, plaintext: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    
    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, plaintext).expect("encryption failure");
    
    // Explicitly zeroize key since derive_key returns raw array
    let mut k = key;
    k.zeroize();
    
    let mut out = Vec::new();
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    out
}

pub fn decrypt_file_data(password: &str, data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if data.len() < 16 + 12 {
        return Err("Data too short");
    }
    let salt = &data[0..16];
    let nonce_bytes = &data[16..28];
    let ciphertext = &data[28..];
    
    let key = derive_key(password, salt);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let nonce = Nonce::from_slice(nonce_bytes);
    
    let res = cipher.decrypt(nonce, ciphertext).map_err(|_| "Decryption failed (wrong password?)");
    
    let mut k = key;
    k.zeroize();
    
    res
}

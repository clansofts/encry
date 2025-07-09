use aes_gcm::aead::{Aead, KeyInit, OsRng, rand_core::RngCore};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM with 256-bit key

use base64::{Engine as _, engine::general_purpose};
use hkdf::Hkdf;
use sha2::Sha256;

/// Derives a 256-bit (32-byte) AES key using HKDF-SHA256
pub fn derive_key(ikm_b64: &str, info_b64: &str) -> [u8; 32] {
    let ikm = general_purpose::STANDARD
        .decode(&ikm_b64)
        .expect("invalid base64 IKM");
    let info = general_purpose::STANDARD
        .decode(&info_b64)
        .expect("invalid base64 info");

    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut key = [0u8; 32];
    hkdf.expand(&info, &mut key).expect("HKDF expand failed");

    key
}

/// Decrypts AES-GCM-encrypted data from a base64 input containing [IV | Ciphertext | Tag]
pub fn decrypt_aes_gcm(encoded_b64: &str, key: &[u8; 32]) -> Vec<u8> {
    let data = general_purpose::STANDARD
        .decode(encoded_b64)
        .expect("invalid base64 ciphertext");
    let (iv, ciphertext_and_tag) = data.split_at(12); // 12-byte IV

    let key_arr = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key_arr);
    let nonce = Nonce::from_slice(iv);

    cipher
        .decrypt(nonce, ciphertext_and_tag)
        .expect("decryption failed")
}
/// Encrypts plaintext using AES-GCM with a random 12-byte IV.
/// Returns base64-encoded string of [IV | Ciphertext | Tag]
pub fn encrypt_aes_gcm(plaintext: &[u8], key: &[u8; 32]) -> String {
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);

    let key_arr = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key_arr);
    let nonce = Nonce::from_slice(&iv);

    let ciphertext = cipher.encrypt(nonce, plaintext).expect("encryption failed");

    let mut result = Vec::new();
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ciphertext);

    general_purpose::STANDARD.encode(&result)
}

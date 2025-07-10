use aes_gcm::aead::{Aead, KeyInit, OsRng, rand_core::RngCore};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{Engine as _, engine::general_purpose};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::Sha256;

use crate::kryptor::errors::EncryptionError;

pub type Result<T> = std::result::Result<T, EncryptionError>;

#[derive(Debug, Clone)]
pub struct KryptorService {
    ikm_base64: String,
    context_base64: String,
    derived_key: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub data: String,
    pub context: String,
}

impl KryptorService {
    pub fn new(ikm_base64: String, context_base64: String) -> Self {
        Self {
            ikm_base64,
            context_base64,
            derived_key: None,
        }
    }

    pub fn with_context<T: Serialize>(ikm_base64: String, context: &T) -> Result<Self> {
        let context_json = serde_json::to_string(context)?;
        let context_base64 = general_purpose::STANDARD.encode(&context_json);
        Ok(Self::new(ikm_base64, context_base64))
    }

    /// Derives a 256-bit (32-byte) AES key using HKDF-SHA256
    pub fn derive_key(&mut self) -> Result<[u8; 32]> {
        if let Some(key) = self.derived_key {
            return Ok(key);
        }

        let ikm = general_purpose::STANDARD.decode(&self.ikm_base64)?;
        let info = general_purpose::STANDARD.decode(&self.context_base64)?;

        let hkdf = Hkdf::<Sha256>::new(None, &ikm);
        let mut key = [0u8; 32];
        hkdf.expand(&info, &mut key)?;

        self.derived_key = Some(key);
        Ok(key)
    }

    /// Generic method to encrypt any serializable type
    pub fn encrypt_json<T: Serialize>(&mut self, data: &T) -> Result<String> {
        let json_string = serde_json::to_string(data)?;
        let json_base64 = general_purpose::STANDARD.encode(&json_string);
        self.encrypt_bytes(json_base64.as_bytes())
    }

    /// Generic method to decrypt and deserialize to any type
    pub fn decrypt_json<T: DeserializeOwned>(&mut self, encrypted_base64: &str) -> Result<T> {
        let decrypted_bytes = self.decrypt_bytes(encrypted_base64)?;
        let json_base64 = String::from_utf8(decrypted_bytes)?;
        let json_bytes = general_purpose::STANDARD.decode(&json_base64)?;
        let json_string = String::from_utf8(json_bytes)?;
        let data: T = serde_json::from_str(&json_string)?;
        Ok(data)
    }

    /// Encrypts raw bytes using AES-GCM with a random 12-byte IV.
    /// Returns base64-encoded string of [IV | Ciphertext | Tag]
    pub fn encrypt_bytes(&mut self, plaintext: &[u8]) -> Result<String> {
        let key = self.derive_key()?;
        let mut iv = [0u8; 12];
        OsRng.fill_bytes(&mut iv);

        let key_arr = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(key_arr);
        let nonce = Nonce::from_slice(&iv);

        let ciphertext = cipher.encrypt(nonce, plaintext)?;

        let mut result = Vec::new();
        result.extend_from_slice(&iv);
        result.extend_from_slice(&ciphertext);

        Ok(general_purpose::STANDARD.encode(&result))
    }

    /// Decrypts AES-GCM-encrypted data from a base64 input containing [IV | Ciphertext | Tag]
    pub fn decrypt_bytes(&mut self, encoded_b64: &str) -> Result<Vec<u8>> {
        let key = self.derive_key()?;
        let data = general_purpose::STANDARD.decode(encoded_b64)?;
        let (iv, ciphertext_and_tag) = data.split_at(12); // 12-byte IV

        let key_arr = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(key_arr);
        let nonce = Nonce::from_slice(iv);

        let plaintext = cipher.decrypt(nonce, ciphertext_and_tag)?;

        Ok(plaintext)
    }

    /// Creates an EncryptedData structure with both encrypted data and context
    pub fn create_encrypted_package<T: Serialize>(&mut self, data: &T) -> Result<EncryptedData> {
        let encrypted_data = self.encrypt_json(data)?;
        Ok(EncryptedData {
            data: encrypted_data,
            context: self.context_base64.clone(),
        })
    }

    /// Decrypts an EncryptedData package
    pub fn decrypt_package<T: DeserializeOwned>(&mut self, package: &EncryptedData) -> Result<T> {
        // Create a new service with the package's context
        let mut service = Self::new(self.ikm_base64.clone(), package.context.clone());
        service.decrypt_json(&package.data)
    }
}

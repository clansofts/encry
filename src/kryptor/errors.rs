use std::fmt;

#[derive(Debug)]
pub enum EncryptionError {
    SerializationError(serde_json::Error),
    Base64DecodeError(base64::DecodeError),
    HkdfError(hkdf::InvalidLength),
    EncryptionError(aes_gcm::Error),
    DecryptionError(aes_gcm::Error),
    AesGcmError(aes_gcm::Error),
    Utf8Error(std::string::FromUtf8Error),
    Other(String),
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            EncryptionError::Base64DecodeError(e) => write!(f, "Base64 decode error: {}", e),
            EncryptionError::HkdfError(e) => write!(f, "HKDF error: {}", e),
            EncryptionError::EncryptionError(e) => write!(f, "Encryption error: {}", e),
            EncryptionError::DecryptionError(e) => write!(f, "Decryption error: {}", e),
            EncryptionError::AesGcmError(e) => write!(f, "AES-GCM error: {:?}", e),
            EncryptionError::Utf8Error(e) => write!(f, "UTF-8 error: {}", e),
            EncryptionError::Other(s) => write!(f, "Other error: {}", s),
        }
    }
}

impl std::error::Error for EncryptionError {}

impl From<serde_json::Error> for EncryptionError {
    fn from(err: serde_json::Error) -> Self {
        EncryptionError::SerializationError(err)
    }
}

impl From<base64::DecodeError> for EncryptionError {
    fn from(err: base64::DecodeError) -> Self {
        EncryptionError::Base64DecodeError(err)
    }
}

impl From<hkdf::InvalidLength> for EncryptionError {
    fn from(err: hkdf::InvalidLength) -> Self {
        EncryptionError::HkdfError(err)
    }
}

impl From<aes_gcm::Error> for EncryptionError {
    fn from(err: aes_gcm::Error) -> Self {
        EncryptionError::AesGcmError(err)
    }
}

impl From<std::string::FromUtf8Error> for EncryptionError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        EncryptionError::Utf8Error(err)
    }
}
impl From<String> for EncryptionError {
    fn from(err: String) -> Self {
        EncryptionError::Other(err)
    }
}

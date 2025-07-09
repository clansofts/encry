mod utilities;

use crate::utilities::{decrypt_aes_gcm, derive_key, encrypt_aes_gcm};
use base64::Engine; // For base64 encoding/decoding

// AES-GCM with 256-bit key

fn main() {
    let ikm_b64 = String::from("rph2pwTQCx+TD/lk+7o9igzQw5A7FU3+S+Z24Cf9Duk=");
    let info_b64 = String::from("eyJiYXIiOiJiYXoifQ==");
    let derived_key = derive_key(ikm_b64.as_str(), info_b64.as_str());

    // Decryption
    let encrypted_b64 = "1pEqzFnkQEa5RA35ynhOd0Ye907S9PvWIq5dRPDP3Q==";
    let decrypted = decrypt_aes_gcm(encrypted_b64, &derived_key);
    println!("🔓 Decrypted: {}", String::from_utf8_lossy(&decrypted));

    // Encryption
    let plaintext = b"Mwaura S W";

    println!("Plaintext: {}", String::from_utf8_lossy(plaintext));
    let encrypted_new = encrypt_aes_gcm(plaintext, &derived_key);
    println!("🔐 Encrypted: {}", encrypted_new);

    // Optional: confirm round-trip
    let round_trip = decrypt_aes_gcm(&encrypted_new, &derived_key);

    println!(
        "🔓 Decrypted Round Trip : {}",
        String::from_utf8_lossy(&round_trip)
    );
    assert_eq!(plaintext, &round_trip[..]);
}

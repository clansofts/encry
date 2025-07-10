mod examples;
mod kryptor;
mod models;

use examples::demonstrate_advanced_encryption;
use models::{EncryptionContext, EventStore, Profile};
use uuid::{NoContext, Timestamp, Uuid};

use crate::kryptor::{config::AppConfig, errors::EncryptionError, utilities::KryptorService};

fn create_sample_profile() -> Profile {
    Profile::new(
        "Mwaura S W".to_string(),
        "1990-01-01".to_string(),
        "smwaura@outlook.com".to_string(),
        vec!["+254712345678".to_string(), "+254712345679".to_string()],
    )
}

fn generate_aggregate_key() -> String {
    let ts = Timestamp::from_unix(NoContext, 1497624119, 1234);
    Uuid::new_v7(ts).to_string()
}

fn demonstrate_encryption() -> Result<(), EncryptionError> {
    // Configuration
    let config = AppConfig::new();
    let aggregate_key = generate_aggregate_key();

    // Create sample data
    let profile = create_sample_profile();
    let event_store = EventStore::with_profile(aggregate_key.clone(), profile);

    // Create encryption context
    let context = EncryptionContext::new(aggregate_key);

    // Create encryption service
    let mut kryptor_service = KryptorService::with_context(config.ikm_base64, &context)?;

    println!("=== Original Data ===");
    let json_string = serde_json::to_string_pretty(&event_store)?;
    println!("{}", json_string);

    // Encrypt the entire EventStore
    println!("\n=== Encryption Process ===");
    let encrypted_data = kryptor_service.encrypt_json(&event_store)?;
    println!("🔐 Encrypted: {}", encrypted_data);

    // Decrypt and verify
    println!("\n=== Decryption Process ===");
    let decrypted_event_store: EventStore = kryptor_service.decrypt_json(&encrypted_data)?;
    let decrypted_json = serde_json::to_string_pretty(&decrypted_event_store)?;
    println!("� Decrypted:");
    println!("{}", decrypted_json);

    // Verify data integrity
    let original_json = serde_json::to_string(&event_store)?;
    let decrypted_json_compact = serde_json::to_string(&decrypted_event_store)?;

    if original_json == decrypted_json_compact {
        println!("\n✅ Round-trip encryption/decryption successful!");
    } else {
        println!("\n❌ Data integrity check failed!");
    }

    // Demonstrate encrypted package
    println!("\n=== Encrypted Package Demo ===");
    let package = kryptor_service.create_encrypted_package(&event_store)?;
    println!("Package created with context: {}", package.context);

    let _recovered_data: EventStore = kryptor_service.decrypt_package(&package)?;
    println!("Successfully recovered data from package");

    Ok(())
}

fn main() {
    println!("🔐 Encryption Service Demo\n");

    // Run basic encryption demo
    match demonstrate_encryption() {
        Ok(()) => println!("✅ Basic encryption demo completed successfully!"),
        Err(e) => eprintln!("❌ Basic encryption error: {}", e),
    }

    println!("\n{}", "=".repeat(60));

    // Run advanced encryption examples
    match demonstrate_advanced_encryption() {
        Ok(()) => println!("\n🎉 All advanced encryption operations completed successfully!"),
        Err(e) => eprintln!("❌ Advanced encryption error: {}", e),
    }
}

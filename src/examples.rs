use crate::{
    kryptor::{config::AppConfig, errors::EncryptionError, utilities::KryptorService},
    models::{EncryptionContext, Profile},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAccount {
    pub user_id: String,
    pub username: String,
    pub email: String,
    pub created_at: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub transaction_id: String,
    pub amount: f64,
    pub currency: String,
    pub from_account: String,
    pub to_account: String,
    pub timestamp: String,
}

pub struct EncryptionService {
    config: AppConfig,
}

impl EncryptionService {
    pub fn new() -> Self {
        Self {
            config: AppConfig::new(),
        }
    }

    /// Encrypt any serializable data with a custom context
    pub fn encrypt_with_context<T, C>(
        &self,
        data: &T,
        context: &C,
    ) -> Result<String, EncryptionError>
    where
        T: Serialize,
        C: Serialize,
    {
        let mut service = KryptorService::with_context(self.config.ikm_base64.clone(), context)?;
        service.encrypt_json(data)
    }

    /// Decrypt data with a custom context
    pub fn decrypt_with_context<T, C>(
        &self,
        encrypted_data: &str,
        context: &C,
    ) -> Result<T, EncryptionError>
    where
        T: serde::de::DeserializeOwned,
        C: Serialize,
    {
        let mut service = KryptorService::with_context(self.config.ikm_base64.clone(), context)?;
        service.decrypt_json(encrypted_data)
    }

    /// Encrypt user account data
    pub fn encrypt_user_account(&self, account: &UserAccount) -> Result<String, EncryptionError> {
        let context = EncryptionContext::new(format!("user:{}", account.user_id));
        self.encrypt_with_context(account, &context)
    }

    /// Decrypt user account data
    pub fn decrypt_user_account(
        &self,
        encrypted_data: &str,
        user_id: &str,
    ) -> Result<UserAccount, EncryptionError> {
        let context = EncryptionContext::new(format!("user:{}", user_id));
        self.decrypt_with_context(encrypted_data, &context)
    }

    /// Encrypt transaction data
    pub fn encrypt_transaction(
        &self,
        transaction: &Transaction,
    ) -> Result<String, EncryptionError> {
        let context = EncryptionContext::new(format!("tx:{}", transaction.transaction_id));
        self.encrypt_with_context(transaction, &context)
    }

    /// Decrypt transaction data
    pub fn decrypt_transaction(
        &self,
        encrypted_data: &str,
        transaction_id: &str,
    ) -> Result<Transaction, EncryptionError> {
        let context = EncryptionContext::new(format!("tx:{}", transaction_id));
        self.decrypt_with_context(encrypted_data, &context)
    }
}

/// Example demonstrating different types of data encryption
pub fn demonstrate_advanced_encryption() -> Result<(), EncryptionError> {
    let service = EncryptionService::new();

    // Example 1: User Account Encryption
    println!("=== User Account Encryption ===");
    let user_account = UserAccount {
        user_id: "user_123".to_string(),
        username: "john_doe".to_string(),
        email: "john@example.com".to_string(),
        created_at: "2024-01-01T00:00:00Z".to_string(),
        metadata: serde_json::json!({
            "preferences": {
                "theme": "dark",
                "notifications": true
            },
            "last_login": "2024-07-10T10:30:00Z"
        }),
    };

    let encrypted_account = service.encrypt_user_account(&user_account)?;
    println!("Encrypted Account: {}", encrypted_account);

    let decrypted_account = service.decrypt_user_account(&encrypted_account, "user_123")?;
    println!("Decrypted Account: {:?}", decrypted_account);

    // Example 2: Transaction Encryption
    println!("\n=== Transaction Encryption ===");
    let transaction = Transaction {
        transaction_id: "tx_456".to_string(),
        amount: 1250.75,
        currency: "USD".to_string(),
        from_account: "acc_789".to_string(),
        to_account: "acc_012".to_string(),
        timestamp: "2024-07-10T14:30:00Z".to_string(),
    };

    let encrypted_transaction = service.encrypt_transaction(&transaction)?;
    println!("Encrypted Transaction: {}", encrypted_transaction);

    let decrypted_transaction = service.decrypt_transaction(&encrypted_transaction, "tx_456")?;
    println!("Decrypted Transaction: {:?}", decrypted_transaction);

    // Example 3: Bulk Encryption with Different Contexts
    println!("\n=== Bulk Encryption Demo ===");
    let profiles = vec![
        Profile::new(
            "Alice Smith".to_string(),
            "1985-03-15".to_string(),
            "alice@example.com".to_string(),
            vec!["+1234567890".to_string()],
        ),
        Profile::new(
            "Bob Johnson".to_string(),
            "1990-07-22".to_string(),
            "bob@example.com".to_string(),
            vec!["+0987654321".to_string()],
        ),
        Profile::new(
            "Carol Williams".to_string(),
            "1988-11-30".to_string(),
            "carol@example.com".to_string(),
            vec!["+1122334455".to_string()],
        ),
    ];

    let mut encrypted_profiles = Vec::new();
    for (index, profile) in profiles.iter().enumerate() {
        let context = EncryptionContext::new(format!("profile_{}", index));
        let encrypted = service.encrypt_with_context(profile, &context)?;
        println!(
            "Encrypted Profile {}: {}",
            index,
            encrypted.chars().take(50).collect::<String>() + "..."
        );
        encrypted_profiles.push((encrypted, index));
    }

    // Decrypt them back
    println!("\nDecrypting profiles:");
    for (encrypted, index) in encrypted_profiles {
        let context = EncryptionContext::new(format!("profile_{}", index));
        let decrypted: Profile = service.decrypt_with_context(&encrypted, &context)?;
        println!("Profile {}: {:?}", index, decrypted);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_account_encryption_roundtrip() -> Result<(), EncryptionError> {
        let service = EncryptionService::new();
        let account = UserAccount {
            user_id: "test_user".to_string(),
            username: "test".to_string(),
            email: "test@example.com".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            metadata: serde_json::json!({"test": true}),
        };

        let encrypted = service.encrypt_user_account(&account)?;
        let decrypted = service.decrypt_user_account(&encrypted, "test_user")?;

        assert_eq!(account.user_id, decrypted.user_id);
        assert_eq!(account.username, decrypted.username);
        assert_eq!(account.email, decrypted.email);

        Ok(())
    }

    #[test]
    fn test_transaction_encryption_roundtrip() -> Result<(), EncryptionError> {
        let service = EncryptionService::new();
        let transaction = Transaction {
            transaction_id: "test_tx".to_string(),
            amount: 100.50,
            currency: "USD".to_string(),
            from_account: "from".to_string(),
            to_account: "to".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        let encrypted = service.encrypt_transaction(&transaction)?;
        let decrypted = service.decrypt_transaction(&encrypted, "test_tx")?;

        assert_eq!(transaction.transaction_id, decrypted.transaction_id);
        assert_eq!(transaction.amount, decrypted.amount);
        assert_eq!(transaction.currency, decrypted.currency);

        Ok(())
    }

    #[test]
    fn test_different_contexts_produce_different_ciphertexts() -> Result<(), EncryptionError> {
        let service = EncryptionService::new();
        let data = Profile::new(
            "Test".to_string(),
            "2000-01-01".to_string(),
            "test@example.com".to_string(),
            vec![],
        );

        let context1 = EncryptionContext::new("context1".to_string());
        let context2 = EncryptionContext::new("context2".to_string());

        let encrypted1 = service.encrypt_with_context(&data, &context1)?;
        let encrypted2 = service.encrypt_with_context(&data, &context2)?;

        // Same data with different contexts should produce different ciphertexts
        assert_ne!(encrypted1, encrypted2);

        Ok(())
    }
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventStore {
    pub aggregated_key: String,
    pub aggregate_type: String,
    pub version: i32,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub dob: String,
    pub email: String,
    pub phones: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionContext {
    pub keygen: String,
}

impl EncryptionContext {
    pub fn new(keygen: String) -> Self {
        Self { keygen }
    }
}

impl EventStore {
    pub fn new(aggregated_key: String, aggregate_type: String, version: i32, payload: serde_json::Value) -> Self {
        Self {
            aggregated_key,
            aggregate_type,
            version,
            payload,
        }
    }

    pub fn with_profile(aggregated_key: String, profile: Profile) -> Self {
        let payload = serde_json::to_value(profile).unwrap_or(serde_json::Value::Null);
        Self::new(aggregated_key, "Profile".to_string(), 0, payload)
    }
}

impl Profile {
    pub fn new(name: String, dob: String, email: String, phones: Vec<String>) -> Self {
        Self { name, dob, email, phones }
    }
}

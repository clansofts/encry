pub struct AppConfig {
    pub ikm_base64: String,
}

impl AppConfig {
    pub fn new() -> Self {
        Self {
            ikm_base64: "rph2pwTQCx+TD/lk+7o9igzQw5A7FU3+S+Z24Cf9Duk=".to_string(),
        }
    }

    pub fn with_ikm(ikm_base64: String) -> Self {
        Self { ikm_base64 }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self::new()
    }
}

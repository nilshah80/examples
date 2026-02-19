use std::env;

pub struct Config {
    pub client_id: String,
    pub client_secret: String,
    pub subject: String,
    pub port: u16,
    pub sidecar_url: String,
}

impl Config {
    pub fn load() -> Self {
        let _ = dotenvy::dotenv();
        Self {
            client_id: env::var("CLIENT_ID")
                .unwrap_or_else(|_| "external-partner-test".into()),
            client_secret: env::var("CLIENT_SECRET")
                .unwrap_or_else(|_| "external-partner-hmac-secret-key-32chars!".into()),
            subject: env::var("SUBJECT").unwrap_or_else(|_| "hmac-user".into()),
            port: env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(3503),
            sidecar_url: env::var("SIDECAR_URL")
                .unwrap_or_else(|_| "http://localhost:8141".into()),
        }
    }
}

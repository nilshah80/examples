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
            client_id: env::var("CLIENT_ID").unwrap_or_else(|_| "dev-client".into()),
            client_secret: env::var("CLIENT_SECRET")
                .unwrap_or_else(|_| "DevSec-LwgT7vXGZk2njwglKWZBYW7q1sdNTElTQ!".into()),
            subject: env::var("SUBJECT").unwrap_or_else(|_| "test-user".into()),
            port: env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(3502),
            sidecar_url: env::var("SIDECAR_URL")
                .unwrap_or_else(|_| "http://localhost:8141".into()),
        }
    }
}

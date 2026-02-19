use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Session Context ─────────────────────────────────────

pub struct SessionContext {
    pub session_id: String,
    pub session_key: [u8; 32],
    pub kid: String,
    pub client_id: String,
    pub authenticated: bool,
    pub expires_in_sec: i64,
}

impl SessionContext {
    pub fn zeroize(&mut self) {
        self.session_key.fill(0);
    }
}

// ── Step Result ─────────────────────────────────────────

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StepResult {
    pub step: u8,
    pub name: String,
    pub request_headers: HashMap<String, String>,
    pub request_body_plaintext: String,
    pub request_body_encrypted: String,
    pub response_headers: HashMap<String, String>,
    pub response_body_encrypted: String,
    pub response_body_decrypted: String,
    pub duration_ms: u128,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ── Session Result (Steps 1 & 4) ────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResult {
    pub step: u8,
    pub name: String,
    pub success: bool,
    pub duration_ms: u128,
    pub session_id: String,
    pub kid: String,
    pub authenticated: bool,
    pub expires_in_sec: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ── API DTOs ────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInitRequest {
    pub client_public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInitResponse {
    pub session_id: String,
    pub server_public_key: String,
    #[allow(dead_code)]
    pub enc_alg: Option<String>,
    pub expires_in_sec: i64,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub payload: String,
}

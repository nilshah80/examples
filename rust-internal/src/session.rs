use std::time::SystemTime;

use crate::config::Config;
use crate::crypto;
use crate::models::{SessionContext, SessionInitRequest, SessionInitResponse};

/// Step 1: Anonymous ECDH session initialization.
pub async fn init_session(
    config: &Config,
    http_client: &reqwest::Client,
) -> Result<SessionContext, String> {
    let key_pair = crypto::generate_ecdh_keypair();
    let pub_key_bytes = crypto::export_public_key(&key_pair);
    let nonce = crypto::generate_nonce();
    let ts = millis_now();

    let body = SessionInitRequest {
        client_public_key: crypto::to_base64(&pub_key_bytes),
    };

    let response = http_client
        .post(format!("{}/api/v1/session/init", config.sidecar_url))
        .header("Content-Type", "application/json")
        .header("X-Idempotency-Key", format!("{ts}.{nonce}"))
        .header("X-ClientId", &config.client_id)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Session init request failed: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Session init failed: HTTP {status} — {body}"));
    }

    let data: SessionInitResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse session init response: {e}"))?;

    derive_session(key_pair, &data, &config.client_id, false)
}

/// Step 4: Authenticated session refresh with Bearer + X-Subject.
pub async fn refresh_session(
    config: &Config,
    http_client: &reqwest::Client,
    access_token: &str,
    old_session: &mut Option<SessionContext>,
) -> Result<SessionContext, String> {
    let key_pair = crypto::generate_ecdh_keypair();
    let pub_key_bytes = crypto::export_public_key(&key_pair);
    let nonce = crypto::generate_nonce();
    let ts = millis_now();

    let body = SessionInitRequest {
        client_public_key: crypto::to_base64(&pub_key_bytes),
    };

    let response = http_client
        .post(format!("{}/api/v1/session/init", config.sidecar_url))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {access_token}"))
        .header("X-Subject", &config.subject)
        .header("X-Idempotency-Key", format!("{ts}.{nonce}"))
        .header("X-ClientId", &config.client_id)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Session refresh request failed: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Session refresh failed: HTTP {status} — {body}"));
    }

    // Zeroize old session key
    if let Some(s) = old_session {
        s.zeroize();
    }

    let data: SessionInitResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse session refresh response: {e}"))?;

    derive_session(key_pair, &data, &config.client_id, true)
}

fn derive_session(
    key_pair: crypto::EcdhKeyPair,
    data: &SessionInitResponse,
    client_id: &str,
    authenticated: bool,
) -> Result<SessionContext, String> {
    let mut shared = crypto::compute_shared_secret(key_pair, &data.server_public_key)?;
    let session_key = crypto::derive_session_key(&mut shared, &data.session_id, client_id)?;

    Ok(SessionContext {
        session_id: data.session_id.clone(),
        session_key,
        kid: format!("session:{}", data.session_id),
        client_id: client_id.to_string(),
        authenticated,
        expires_in_sec: data.expires_in_sec,
    })
}

fn millis_now() -> String {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string()
}

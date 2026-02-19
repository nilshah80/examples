use std::collections::HashMap;
use std::time::{Instant, SystemTime};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use crate::config::Config;
use crate::crypto;
use crate::models::{EncryptedPayload, SessionContext, StepResult};

/// Step 2: Token Issue (Basic Auth + GCM).
pub async fn issue_token(
    config: &Config,
    http_client: &reqwest::Client,
    session: &SessionContext,
    plaintext: &str,
) -> StepResult {
    let basic_auth = format!(
        "Basic {}",
        B64.encode(format!("{}:{}", config.client_id, config.client_secret))
    );
    let mut auth = HashMap::new();
    auth.insert("Authorization".to_string(), basic_auth);

    post_encrypted(
        config,
        http_client,
        "/v1/token/issue",
        session,
        plaintext,
        auth,
        2,
        "Token Issue (Basic Auth + GCM)",
    )
    .await
}

/// Step 3: Token Introspection (Bearer + GCM).
pub async fn introspect_token(
    config: &Config,
    http_client: &reqwest::Client,
    session: &SessionContext,
    plaintext: &str,
    access_token: &str,
) -> StepResult {
    let mut auth = HashMap::new();
    auth.insert(
        "Authorization".to_string(),
        format!("Bearer {access_token}"),
    );

    post_encrypted(
        config,
        http_client,
        "/v1/introspect",
        session,
        plaintext,
        auth,
        3,
        "Token Introspection (Bearer + GCM)",
    )
    .await
}

/// Step 5: Token Refresh (Bearer + GCM).
pub async fn refresh_token(
    config: &Config,
    http_client: &reqwest::Client,
    session: &SessionContext,
    plaintext: &str,
    access_token: &str,
) -> StepResult {
    let mut auth = HashMap::new();
    auth.insert(
        "Authorization".to_string(),
        format!("Bearer {access_token}"),
    );

    post_encrypted(
        config,
        http_client,
        "/v1/token",
        session,
        plaintext,
        auth,
        5,
        "Token Refresh (Bearer + GCM)",
    )
    .await
}

/// Step 6: Token Revocation (Bearer + GCM).
pub async fn revoke_token(
    config: &Config,
    http_client: &reqwest::Client,
    session: &SessionContext,
    plaintext: &str,
    access_token: &str,
) -> StepResult {
    let mut auth = HashMap::new();
    auth.insert(
        "Authorization".to_string(),
        format!("Bearer {access_token}"),
    );

    post_encrypted(
        config,
        http_client,
        "/v1/revoke",
        session,
        plaintext,
        auth,
        6,
        "Token Revocation (Bearer + GCM)",
    )
    .await
}

/// Core encrypted POST: encrypt request, send, decrypt response.
async fn post_encrypted(
    config: &Config,
    http_client: &reqwest::Client,
    path: &str,
    session: &SessionContext,
    plaintext: &str,
    auth_headers: HashMap<String, String>,
    step_num: u8,
    step_name: &str,
) -> StepResult {
    let start = Instant::now();

    let nonce = crypto::generate_nonce();
    let ts = millis_now();
    let aad = crypto::build_aad(&ts, &nonce, &session.kid, &session.client_id);

    // Encrypt request body
    let encrypted = match crypto::encrypt(plaintext, &session.session_key, &aad) {
        Ok(enc) => enc,
        Err(e) => return error_result(step_num, step_name, plaintext, &start, &e),
    };

    // Build request headers
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    headers.insert("X-Kid".to_string(), session.kid.clone());
    headers.insert("X-Idempotency-Key".to_string(), format!("{ts}.{nonce}"));
    headers.insert("X-ClientId".to_string(), session.client_id.clone());
    for (k, v) in &auth_headers {
        headers.insert(k.clone(), v.clone());
    }

    let request_body = serde_json::to_string(&EncryptedPayload {
        payload: encrypted.clone(),
    })
    .unwrap();

    // Send HTTP POST
    let url = format!("{}/api{path}", config.sidecar_url);
    let mut req = http_client.post(&url);
    for (k, v) in &headers {
        if k.eq_ignore_ascii_case("Content-Type") {
            continue;
        }
        req = req.header(k.as_str(), v.as_str());
    }
    req = req
        .header("Content-Type", "application/json")
        .body(request_body);

    let response = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return error_result(step_num, step_name, plaintext, &start, &e.to_string());
        }
    };

    // Extract response headers
    let resp_headers = extract_response_headers(&response);
    let status = response.status();
    let response_body_str = response.text().await.unwrap_or_default();

    if !status.is_success() {
        return StepResult {
            step: step_num,
            name: step_name.to_string(),
            request_headers: headers,
            request_body_plaintext: plaintext.to_string(),
            request_body_encrypted: encrypted,
            response_headers: resp_headers,
            response_body_encrypted: String::new(),
            response_body_decrypted: response_body_str.clone(),
            duration_ms: start.elapsed().as_millis(),
            success: false,
            error: Some(format!("HTTP {status}: {response_body_str}")),
        };
    }

    // Decrypt response
    let (resp_encrypted, decrypted) =
        decrypt_response(&response_body_str, &resp_headers, session);

    StepResult {
        step: step_num,
        name: step_name.to_string(),
        request_headers: headers,
        request_body_plaintext: plaintext.to_string(),
        request_body_encrypted: encrypted,
        response_headers: resp_headers,
        response_body_encrypted: resp_encrypted,
        response_body_decrypted: decrypted,
        duration_ms: start.elapsed().as_millis(),
        success: true,
        error: None,
    }
}

fn decrypt_response(
    response_body: &str,
    resp_headers: &HashMap<String, String>,
    session: &SessionContext,
) -> (String, String) {
    let resp_kid = resp_headers.get("x-kid");
    let resp_idemp = resp_headers.get("x-idempotency-key");

    if let (Some(kid), Some(idemp)) = (resp_kid, resp_idemp) {
        let parts: Vec<&str> = idemp.splitn(2, '.').collect();
        if parts.len() == 2 {
            let resp_aad = crypto::build_aad(parts[0], parts[1], kid, &session.client_id);

            if let Ok(payload) = serde_json::from_str::<EncryptedPayload>(response_body) {
                if let Ok(decrypted) =
                    crypto::decrypt(&payload.payload, &session.session_key, &resp_aad)
                {
                    return (payload.payload, decrypted);
                }
            }
        }
    }

    (String::new(), response_body.to_string())
}

fn extract_response_headers(response: &reqwest::Response) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    for key in ["x-kid", "x-idempotency-key", "content-type"] {
        if let Some(val) = response.headers().get(key) {
            if let Ok(s) = val.to_str() {
                headers.insert(key.to_string(), s.to_string());
            }
        }
    }
    headers
}

fn error_result(
    step_num: u8,
    step_name: &str,
    plaintext: &str,
    start: &Instant,
    error: &str,
) -> StepResult {
    StepResult {
        step: step_num,
        name: step_name.to_string(),
        request_headers: HashMap::new(),
        request_body_plaintext: plaintext.to_string(),
        request_body_encrypted: String::new(),
        response_headers: HashMap::new(),
        response_body_encrypted: String::new(),
        response_body_decrypted: String::new(),
        duration_ms: start.elapsed().as_millis(),
        success: false,
        error: Some(error.to_string()),
    }
}

fn millis_now() -> String {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string()
}

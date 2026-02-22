use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;
use web_sys::{window, Storage};

type HmacSha256 = Hmac<Sha256>;

// ═══════════════════════════════════════════════════════════════════════════
// BUILD-TIME CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

const SIDECAR_URL: &str = match option_env!("WASM_SIDECAR_URL") {
    Some(url) => url,
    None => "http://localhost:3509", // Default fallback
};

const CLIENT_ID: &str = match option_env!("CLIENT_ID") {
    Some(id) => id,
    None => "dev-client", // Default fallback
};

const CLIENT_SECRET: &str = match option_env!("CLIENT_SECRET") {
    Some(secret) => secret,
    None => "DevSec-LwgT7vXGZk2njwglKWZBYW7q1sdNTElTQ!", // Default fallback
};

const SUBJECT: &str = match option_env!("SUBJECT") {
    Some(subj) => subj,
    None => "test-user", // Default fallback
};

// ═══════════════════════════════════════════════════════════════════════════
// WASM STATIC SECRET
// ═══════════════════════════════════════════════════════════════════════════

const WASM_STATIC_SECRET: [u8; 32] = [
    0x2a, 0x7b, 0x91, 0x4c, 0x65, 0xe8, 0x3f, 0xa9,
    0x1d, 0x52, 0xb3, 0x7e, 0x94, 0x0f, 0x6c, 0x28,
    0x83, 0xa4, 0x5d, 0x19, 0xf7, 0x2b, 0x68, 0x9a,
    0x3e, 0xd1, 0x4f, 0x86, 0x5c, 0x20, 0x97, 0xb5,
];

// ═══════════════════════════════════════════════════════════════════════════
// API CALL RESULT
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiCallResult {
    request_headers: BTreeMap<String, String>,
    request_body_plaintext: String,
    request_body_encrypted: String,
    response_headers: BTreeMap<String, String>,
    response_body_encrypted: String,
    response_body_decrypted: String,
}

struct HttpResponseWithHeaders {
    body: String,
    idempotency_key: String,
    kid: String,
    content_type: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// WASM BINDINGS - Configuration Getters
// ═══════════════════════════════════════════════════════════════════════════

#[wasm_bindgen]
pub fn get_sidecar_url() -> String {
    SIDECAR_URL.to_string()
}

#[wasm_bindgen]
pub fn get_client_id() -> String {
    CLIENT_ID.to_string()
}

#[wasm_bindgen]
pub fn get_client_secret() -> String {
    CLIENT_SECRET.to_string()
}

#[wasm_bindgen]
pub fn get_subject() -> String {
    SUBJECT.to_string()
}

// ═══════════════════════════════════════════════════════════════════════════
// WASM BINDINGS - Session Context
// ═══════════════════════════════════════════════════════════════════════════

#[wasm_bindgen]
pub struct SessionContext {
    session_id: String,
    session_key: [u8; 32],
    kid: String,
    client_id: String,
    authenticated: bool,
    expires_in_sec: i64,
}

#[wasm_bindgen]
impl SessionContext {
    #[wasm_bindgen(getter)]
    pub fn session_id(&self) -> String {
        self.session_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn kid(&self) -> String {
        self.kid.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn authenticated(&self) -> bool {
        self.authenticated
    }

    #[wasm_bindgen(getter)]
    pub fn expires_in_sec(&self) -> i64 {
        self.expires_in_sec
    }

    #[wasm_bindgen]
    pub fn encrypt(&self, plaintext: &str, timestamp: &str, nonce: &str) -> Result<String, JsValue> {
        let aad = build_aad(timestamp, nonce, &self.kid, &self.client_id);
        encrypt_aes_gcm(plaintext, &self.session_key, &aad)
            .map_err(|e| JsValue::from_str(&e))
    }

    #[wasm_bindgen]
    pub fn decrypt(&self, ciphertext: &str, timestamp: &str, nonce: &str) -> Result<String, JsValue> {
        let aad = build_aad(timestamp, nonce, &self.kid, &self.client_id);
        decrypt_aes_gcm(ciphertext, &self.session_key, &aad)
            .map_err(|e| JsValue::from_str(&e))
    }

    #[wasm_bindgen]
    pub fn save_to_storage(&self) -> Result<(), JsValue> {
        let storage = get_session_storage()?;

        let encrypted_session_key =
            encrypt_session_key_for_storage(&self.session_key, &self.session_id, &self.client_id)
                .map_err(|e| JsValue::from_str(&e))?;

        storage.set_item("session_id", &self.session_id)?;
        storage.set_item("encrypted_session_key", &encrypted_session_key)?;
        storage.set_item("kid", &self.kid)?;
        storage.set_item("client_id", &self.client_id)?;
        storage.set_item("authenticated", &self.authenticated.to_string())?;
        storage.set_item("expires_in_sec", &self.expires_in_sec.to_string())?;

        log("Session saved to storage (session key encrypted with per-session derived key)");
        Ok(())
    }

    #[wasm_bindgen]
    pub fn load_from_storage() -> Result<SessionContext, JsValue> {
        let storage = get_session_storage()?;

        let session_id = storage.get_item("session_id")?
            .ok_or_else(|| JsValue::from_str("No session found"))?;
        let encrypted_session_key = storage.get_item("encrypted_session_key")?
            .ok_or_else(|| JsValue::from_str("No encrypted session key found"))?;
        let kid = storage.get_item("kid")?
            .ok_or_else(|| JsValue::from_str("No kid found"))?;
        let client_id = storage.get_item("client_id")?
            .ok_or_else(|| JsValue::from_str("No client_id found"))?;
        let authenticated = storage.get_item("authenticated")?
            .ok_or_else(|| JsValue::from_str("No authenticated flag found"))?
            .parse::<bool>()
            .map_err(|_| JsValue::from_str("Invalid authenticated value"))?;
        let expires_in_sec = storage.get_item("expires_in_sec")?
            .ok_or_else(|| JsValue::from_str("No expires_in_sec found"))?
            .parse::<i64>()
            .map_err(|_| JsValue::from_str("Invalid expires_in_sec value"))?;

        let session_key =
            decrypt_session_key_from_storage(&encrypted_session_key, &session_id, &client_id)
                .map_err(|e| JsValue::from_str(&e))?;

        log("Session loaded from storage (session key decrypted with per-session derived key)");

        Ok(SessionContext {
            session_id,
            session_key,
            kid,
            client_id,
            authenticated,
            expires_in_sec,
        })
    }

    #[wasm_bindgen]
    pub fn clear_storage() -> Result<(), JsValue> {
        let storage = get_session_storage()?;
        storage.remove_item("session_id")?;
        storage.remove_item("encrypted_session_key")?;
        storage.remove_item("kid")?;
        storage.remove_item("client_id")?;
        storage.remove_item("authenticated")?;
        storage.remove_item("expires_in_sec")?;
        storage.remove_item("encrypted_access_token")?;
        storage.remove_item("encrypted_refresh_token")?;
        log("Session and tokens cleared from storage");
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HIGH-LEVEL API METHODS
    // ═══════════════════════════════════════════════════════════════════════

    /// Step 2: Issue tokens (HMAC Signature + AES-256-GCM) — External Client
    /// Uses HMAC-SHA256 signature over plaintext body instead of Basic auth
    #[wasm_bindgen]
    pub async fn issue_token(&self, request_body_json: &str) -> Result<String, JsValue> {
        let timestamp = (js_sys::Date::new_0().get_time() as u64).to_string();
        let nonce = uuid::Uuid::new_v4().to_string();

        // Compute HMAC signature over PLAINTEXT body (before encryption)
        let signature = compute_hmac_signature_internal(
            "POST",
            "/api/v1/token/issue",
            &timestamp,
            &nonce,
            request_body_json,
            CLIENT_SECRET,
        );

        // Encrypt request body
        let aad = build_aad(&timestamp, &nonce, &self.kid, &self.client_id);
        let encrypted = encrypt_aes_gcm(request_body_json, &self.session_key, &aad)
            .map_err(|e| JsValue::from_str(&e))?;

        // Build request headers — X-Signature instead of Basic auth
        let mut request_headers = BTreeMap::new();
        request_headers.insert("Content-Type".to_string(), "application/json".to_string());
        request_headers.insert("X-ClientId".to_string(), self.client_id.clone());
        request_headers.insert("X-Idempotency-Key".to_string(), format!("{}.{}", timestamp, nonce));
        request_headers.insert("X-Kid".to_string(), self.kid.clone());
        request_headers.insert("X-Signature".to_string(), signature);

        let headers: Vec<(String, String)> = request_headers.iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let url = format!("{}/api/v1/token/issue", SIDECAR_URL);
        let http_body = serde_json::json!({ "payload": encrypted }).to_string();
        let resp = http_post_with_headers(&url, &http_body, &headers).await?;

        let resp_body: serde_json::Value = serde_json::from_str(&resp.body)
            .map_err(|e| JsValue::from_str(&format!("JSON parse error: {}", e)))?;
        let encrypted_response = resp_body["payload"].as_str()
            .ok_or_else(|| JsValue::from_str("No payload in response"))?;

        let (resp_ts, resp_nonce) = parse_idempotency_key(&resp.idempotency_key)?;
        let resp_aad = build_aad(&resp_ts, &resp_nonce, &self.kid, &self.client_id);
        let decrypted = decrypt_aes_gcm(encrypted_response, &self.session_key, &resp_aad)
            .map_err(|e| JsValue::from_str(&e))?;

        // Extract tokens and store encrypted
        let tokens: serde_json::Value = serde_json::from_str(&decrypted)
            .map_err(|e| JsValue::from_str(&format!("Token parse error: {}", e)))?;
        if let Some(at) = tokens["access_token"].as_str() {
            store_token_to_storage("encrypted_access_token", at, &self.session_id, &self.client_id)?;
        }
        if let Some(rt) = tokens["refresh_token"].as_str() {
            store_token_to_storage("encrypted_refresh_token", rt, &self.session_id, &self.client_id)?;
        }

        log("Tokens issued (HMAC auth) and stored encrypted in sessionStorage");

        let mut response_headers = BTreeMap::new();
        response_headers.insert("x-kid".to_string(), resp.kid);
        response_headers.insert("x-idempotency-key".to_string(), resp.idempotency_key);
        response_headers.insert("content-type".to_string(), resp.content_type);

        let result = ApiCallResult {
            request_headers,
            request_body_plaintext: request_body_json.to_string(),
            request_body_encrypted: encrypted,
            response_headers,
            response_body_encrypted: encrypted_response.to_string(),
            response_body_decrypted: mask_tokens_in_json(&decrypted),
        };

        serde_json::to_string(&result)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }

    /// Step 3: Introspect token (Bearer + AES-256-GCM)
    #[wasm_bindgen]
    pub async fn introspect_token(&self) -> Result<String, JsValue> {
        let access_token = load_token_from_storage(
            "encrypted_access_token", &self.session_id, &self.client_id)?;

        let timestamp = (js_sys::Date::new_0().get_time() as u64).to_string();
        let nonce = uuid::Uuid::new_v4().to_string();

        let request_body = serde_json::json!({ "token": access_token }).to_string();
        let aad = build_aad(&timestamp, &nonce, &self.kid, &self.client_id);
        let encrypted = encrypt_aes_gcm(&request_body, &self.session_key, &aad)
            .map_err(|e| JsValue::from_str(&e))?;

        let mut request_headers = BTreeMap::new();
        request_headers.insert("Content-Type".to_string(), "application/json".to_string());
        request_headers.insert("X-ClientId".to_string(), self.client_id.clone());
        request_headers.insert("X-Idempotency-Key".to_string(), format!("{}.{}", timestamp, nonce));
        request_headers.insert("X-Kid".to_string(), self.kid.clone());
        request_headers.insert("Authorization".to_string(), format!("Bearer {}", access_token));

        let headers: Vec<(String, String)> = request_headers.iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let url = format!("{}/api/v1/introspect", SIDECAR_URL);
        let http_body = serde_json::json!({ "payload": encrypted }).to_string();
        let resp = http_post_with_headers(&url, &http_body, &headers).await?;

        let resp_body: serde_json::Value = serde_json::from_str(&resp.body)
            .map_err(|e| JsValue::from_str(&format!("JSON parse error: {}", e)))?;
        let encrypted_response = resp_body["payload"].as_str()
            .ok_or_else(|| JsValue::from_str("No payload in response"))?;

        let (resp_ts, resp_nonce) = parse_idempotency_key(&resp.idempotency_key)?;
        let resp_aad = build_aad(&resp_ts, &resp_nonce, &self.kid, &self.client_id);
        let decrypted = decrypt_aes_gcm(encrypted_response, &self.session_key, &resp_aad)
            .map_err(|e| JsValue::from_str(&e))?;

        log("Token introspection completed");

        let mut display_headers = request_headers;
        display_headers.insert("Authorization".to_string(), "Bearer [PROTECTED_IN_WASM]".to_string());

        let mut response_headers = BTreeMap::new();
        response_headers.insert("x-kid".to_string(), resp.kid);
        response_headers.insert("x-idempotency-key".to_string(), resp.idempotency_key);
        response_headers.insert("content-type".to_string(), resp.content_type);

        let result = ApiCallResult {
            request_headers: display_headers,
            request_body_plaintext: mask_tokens_in_json(&request_body),
            request_body_encrypted: encrypted,
            response_headers,
            response_body_encrypted: encrypted_response.to_string(),
            response_body_decrypted: decrypted,
        };

        serde_json::to_string(&result)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }

    /// Step 4: Refresh session with authenticated ECDH
    #[wasm_bindgen]
    pub async fn refresh_session(&self) -> Result<SessionContext, JsValue> {
        let access_token = load_token_from_storage(
            "encrypted_access_token", &self.session_id, &self.client_id)?;
        let refresh_token = load_token_from_storage(
            "encrypted_refresh_token", &self.session_id, &self.client_id)?;

        let new_ctx = do_session_init(
            SIDECAR_URL,
            &self.client_id,
            Some(access_token.clone()),
            Some(SUBJECT.to_string()),
        ).await?;

        new_ctx.save_to_storage()?;

        store_token_to_storage(
            "encrypted_access_token", &access_token, &new_ctx.session_id, &new_ctx.client_id)?;
        store_token_to_storage(
            "encrypted_refresh_token", &refresh_token, &new_ctx.session_id, &new_ctx.client_id)?;

        log("Session refreshed, tokens migrated to new session key");
        Ok(new_ctx)
    }

    /// Step 5: Refresh tokens (Bearer + AES-256-GCM)
    #[wasm_bindgen]
    pub async fn refresh_tokens(&self) -> Result<String, JsValue> {
        let access_token = load_token_from_storage(
            "encrypted_access_token", &self.session_id, &self.client_id)?;
        let refresh_token = load_token_from_storage(
            "encrypted_refresh_token", &self.session_id, &self.client_id)?;

        let timestamp = (js_sys::Date::new_0().get_time() as u64).to_string();
        let nonce = uuid::Uuid::new_v4().to_string();

        let request_body = serde_json::json!({
            "grant_type": "refresh_token",
            "refresh_token": refresh_token
        }).to_string();
        let aad = build_aad(&timestamp, &nonce, &self.kid, &self.client_id);
        let encrypted = encrypt_aes_gcm(&request_body, &self.session_key, &aad)
            .map_err(|e| JsValue::from_str(&e))?;

        let mut request_headers = BTreeMap::new();
        request_headers.insert("Content-Type".to_string(), "application/json".to_string());
        request_headers.insert("X-ClientId".to_string(), self.client_id.clone());
        request_headers.insert("X-Idempotency-Key".to_string(), format!("{}.{}", timestamp, nonce));
        request_headers.insert("X-Kid".to_string(), self.kid.clone());
        request_headers.insert("Authorization".to_string(), format!("Bearer {}", access_token));

        let headers: Vec<(String, String)> = request_headers.iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let url = format!("{}/api/v1/token", SIDECAR_URL);
        let http_body = serde_json::json!({ "payload": encrypted }).to_string();
        let resp = http_post_with_headers(&url, &http_body, &headers).await?;

        let resp_body: serde_json::Value = serde_json::from_str(&resp.body)
            .map_err(|e| JsValue::from_str(&format!("JSON parse error: {}", e)))?;
        let encrypted_response = resp_body["payload"].as_str()
            .ok_or_else(|| JsValue::from_str("No payload in response"))?;

        let (resp_ts, resp_nonce) = parse_idempotency_key(&resp.idempotency_key)?;
        let resp_aad = build_aad(&resp_ts, &resp_nonce, &self.kid, &self.client_id);
        let decrypted = decrypt_aes_gcm(encrypted_response, &self.session_key, &resp_aad)
            .map_err(|e| JsValue::from_str(&e))?;

        let tokens: serde_json::Value = serde_json::from_str(&decrypted)
            .map_err(|e| JsValue::from_str(&format!("Token parse error: {}", e)))?;
        if let Some(at) = tokens["access_token"].as_str() {
            store_token_to_storage("encrypted_access_token", at, &self.session_id, &self.client_id)?;
        }
        if let Some(rt) = tokens["refresh_token"].as_str() {
            store_token_to_storage("encrypted_refresh_token", rt, &self.session_id, &self.client_id)?;
        }

        log("Tokens refreshed and re-encrypted in sessionStorage");

        let mut display_headers = request_headers;
        display_headers.insert("Authorization".to_string(), "Bearer [PROTECTED_IN_WASM]".to_string());

        let mut response_headers = BTreeMap::new();
        response_headers.insert("x-kid".to_string(), resp.kid);
        response_headers.insert("x-idempotency-key".to_string(), resp.idempotency_key);
        response_headers.insert("content-type".to_string(), resp.content_type);

        let result = ApiCallResult {
            request_headers: display_headers,
            request_body_plaintext: mask_tokens_in_json(&request_body),
            request_body_encrypted: encrypted,
            response_headers,
            response_body_encrypted: encrypted_response.to_string(),
            response_body_decrypted: mask_tokens_in_json(&decrypted),
        };

        serde_json::to_string(&result)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }

    /// Step 6: Revoke tokens (Bearer + AES-256-GCM)
    #[wasm_bindgen]
    pub async fn revoke_tokens(&self) -> Result<String, JsValue> {
        let access_token = load_token_from_storage(
            "encrypted_access_token", &self.session_id, &self.client_id)?;
        let refresh_token = load_token_from_storage(
            "encrypted_refresh_token", &self.session_id, &self.client_id)?;

        let timestamp = (js_sys::Date::new_0().get_time() as u64).to_string();
        let nonce = uuid::Uuid::new_v4().to_string();

        let request_body = serde_json::json!({
            "token": refresh_token,
            "token_type_hint": "refresh_token"
        }).to_string();
        let aad = build_aad(&timestamp, &nonce, &self.kid, &self.client_id);
        let encrypted = encrypt_aes_gcm(&request_body, &self.session_key, &aad)
            .map_err(|e| JsValue::from_str(&e))?;

        let mut request_headers = BTreeMap::new();
        request_headers.insert("Content-Type".to_string(), "application/json".to_string());
        request_headers.insert("X-ClientId".to_string(), self.client_id.clone());
        request_headers.insert("X-Idempotency-Key".to_string(), format!("{}.{}", timestamp, nonce));
        request_headers.insert("X-Kid".to_string(), self.kid.clone());
        request_headers.insert("Authorization".to_string(), format!("Bearer {}", access_token));

        let headers: Vec<(String, String)> = request_headers.iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let url = format!("{}/api/v1/revoke", SIDECAR_URL);
        let http_body = serde_json::json!({ "payload": encrypted }).to_string();
        let resp = http_post_with_headers(&url, &http_body, &headers).await?;

        let resp_body: serde_json::Value = serde_json::from_str(&resp.body).unwrap_or_default();
        let encrypted_response = resp_body.get("payload").and_then(|v| v.as_str());

        let decrypted = if let Some(enc) = encrypted_response {
            let (resp_ts, resp_nonce) = parse_idempotency_key(&resp.idempotency_key)?;
            let resp_aad = build_aad(&resp_ts, &resp_nonce, &self.kid, &self.client_id);
            decrypt_aes_gcm(enc, &self.session_key, &resp_aad)
                .map_err(|e| JsValue::from_str(&e))?
        } else {
            "(empty)".to_string()
        };

        SessionContext::clear_storage()?;

        log("Tokens revoked, session and tokens cleared from storage");

        let mut display_headers = request_headers;
        display_headers.insert("Authorization".to_string(), "Bearer [PROTECTED_IN_WASM]".to_string());

        let mut response_headers = BTreeMap::new();
        response_headers.insert("x-kid".to_string(), resp.kid);
        response_headers.insert("x-idempotency-key".to_string(), resp.idempotency_key);
        response_headers.insert("content-type".to_string(), resp.content_type);

        let result = ApiCallResult {
            request_headers: display_headers,
            request_body_plaintext: mask_tokens_in_json(&request_body),
            request_body_encrypted: encrypted,
            response_headers,
            response_body_encrypted: encrypted_response.unwrap_or("").to_string(),
            response_body_decrypted: decrypted,
        };

        serde_json::to_string(&result)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// WASM BINDINGS - Session Init
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionInitRequest {
    client_public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionInitResponse {
    session_id: String,
    server_public_key: String,
    expires_in_sec: i64,
}

async fn do_session_init(
    sidecar_url: &str,
    client_id: &str,
    access_token: Option<String>,
    subject: Option<String>,
) -> Result<SessionContext, JsValue> {
    let secret = EphemeralSecret::random(&mut OsRng);
    let public_key = secret.public_key();
    let client_public_key_bytes = public_key.to_encoded_point(false);
    let client_public_key_b64 = B64.encode(client_public_key_bytes.as_bytes());

    let req_body = SessionInitRequest {
        client_public_key: client_public_key_b64,
    };
    let req_json = serde_json::to_string(&req_body)
        .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))?;

    let mut headers = Vec::new();
    headers.push(("Content-Type".to_string(), "application/json".to_string()));
    headers.push(("X-ClientId".to_string(), client_id.to_string()));

    let timestamp = js_sys::Date::new_0().get_time() as u64;
    let nonce = uuid::Uuid::new_v4().to_string();
    headers.push(("X-Idempotency-Key".to_string(), format!("{}.{}", timestamp, nonce)));

    let has_access_token = access_token.is_some();
    if let Some(token) = access_token {
        headers.push(("Authorization".to_string(), format!("Bearer {}", token)));
    }
    if let Some(subj) = subject {
        headers.push(("X-Subject".to_string(), subj));
    }

    let url = format!("{}/api/v1/session/init", sidecar_url);
    let response = http_post(&url, &req_json, &headers).await?;

    let resp: SessionInitResponse = serde_json::from_str(&response)
        .map_err(|e| JsValue::from_str(&format!("JSON parse error: {}", e)))?;

    let peer_bytes = B64.decode(&resp.server_public_key)
        .map_err(|e| JsValue::from_str(&format!("Base64 decode error: {}", e)))?;
    let peer_point = EncodedPoint::from_bytes(&peer_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid EC point: {}", e)))?;
    let peer_public_key = Option::from(PublicKey::from_encoded_point(&peer_point))
        .ok_or_else(|| JsValue::from_str("Invalid peer public key"))?;
    let shared = secret.diffie_hellman(&peer_public_key);
    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(shared.raw_secret_bytes());

    let session_key = derive_session_key(&mut shared_secret, &resp.session_id, client_id)
        .map_err(|e| JsValue::from_str(&e))?;

    let kid = format!("session:{}", resp.session_id);
    let authenticated = has_access_token;

    Ok(SessionContext {
        session_id: resp.session_id,
        session_key,
        kid,
        client_id: client_id.to_string(),
        authenticated,
        expires_in_sec: resp.expires_in_sec,
    })
}

#[wasm_bindgen]
pub async fn init_session(
    sidecar_url: &str,
    client_id: &str,
    access_token: Option<String>,
    subject: Option<String>,
) -> Result<SessionContext, JsValue> {
    do_session_init(sidecar_url, client_id, access_token, subject).await
}

// ═══════════════════════════════════════════════════════════════════════════
// CRYPTO HELPERS
// ═══════════════════════════════════════════════════════════════════════════

fn derive_session_key(
    shared_secret: &mut [u8; 32],
    session_id: &str,
    client_id: &str,
) -> Result<[u8; 32], String> {
    let salt = session_id.as_bytes();
    let info = format!("SESSION|A256GCM|{}", client_id);

    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut session_key = [0u8; 32];
    hk.expand(info.as_bytes(), &mut session_key)
        .map_err(|e| format!("HKDF expand failed: {}", e))?;

    shared_secret.fill(0);
    Ok(session_key)
}

fn encrypt_aes_gcm(plaintext: &str, key: &[u8; 32], aad: &[u8]) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("AES key error: {}", e))?;

    let mut iv_bytes = [0u8; 12];
    getrandom::getrandom(&mut iv_bytes).map_err(|e| format!("RNG error: {}", e))?;
    let nonce = Nonce::from(iv_bytes);

    let payload = aes_gcm::aead::Payload {
        msg: plaintext.as_bytes(),
        aad,
    };

    let ciphertext_with_tag = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let mut result = Vec::with_capacity(12 + ciphertext_with_tag.len());
    result.extend_from_slice(&iv_bytes);
    result.extend_from_slice(&ciphertext_with_tag);

    Ok(B64.encode(&result))
}

fn decrypt_aes_gcm(ciphertext_b64: &str, key: &[u8; 32], aad: &[u8]) -> Result<String, String> {
    let encrypted = B64.decode(ciphertext_b64)
        .map_err(|e| format!("Base64 decode error: {}", e))?;
    if encrypted.len() < 28 {
        return Err("Ciphertext too short".into());
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("AES key error: {}", e))?;

    let nonce = Nonce::from(<[u8; 12]>::try_from(&encrypted[..12]).unwrap());
    let payload = aes_gcm::aead::Payload {
        msg: &encrypted[12..],
        aad,
    };

    let plaintext = cipher
        .decrypt(&nonce, payload)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    String::from_utf8(plaintext).map_err(|e| format!("Invalid UTF-8: {}", e))
}

fn build_aad(timestamp: &str, nonce: &str, kid: &str, client_id: &str) -> Vec<u8> {
    format!("{}|{}|{}|{}", timestamp, nonce, kid, client_id).into_bytes()
}

// ═══════════════════════════════════════════════════════════════════════════
// HMAC SIGNATURE (External Client Authentication)
// ═══════════════════════════════════════════════════════════════════════════

/// Internal HMAC computation — used by issue_token, no longer exposed to JS
fn compute_hmac_signature_internal(
    method: &str,
    path: &str,
    timestamp: &str,
    nonce: &str,
    body: &str,
    secret: &str,
) -> String {
    let body_hash = hex::encode(Sha256::digest(body.as_bytes()));
    let string_to_sign = format!(
        "{}\n{}\n{}\n{}\n{}",
        method.to_uppercase(),
        path,
        timestamp,
        nonce,
        body_hash
    );

    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(string_to_sign.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Compute HMAC-SHA256 signature (kept for backward compatibility)
#[wasm_bindgen]
pub fn compute_hmac_signature(
    method: &str,
    path: &str,
    timestamp: &str,
    nonce: &str,
    body: &str,
    secret: &str,
) -> String {
    compute_hmac_signature_internal(method, path, timestamp, nonce, body, secret)
}

// ═══════════════════════════════════════════════════════════════════════════
// SESSION KEY STORAGE ENCRYPTION
// ═══════════════════════════════════════════════════════════════════════════

fn derive_storage_key(session_id: &str, client_id: &str) -> Result<[u8; 32], String> {
    let hk = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), &WASM_STATIC_SECRET);
    let info = format!("STORAGE|A256GCM|{}", client_id);
    let mut storage_key = [0u8; 32];
    hk.expand(info.as_bytes(), &mut storage_key)
        .map_err(|e| format!("HKDF storage key derivation failed: {}", e))?;
    Ok(storage_key)
}

fn encrypt_session_key_for_storage(
    session_key: &[u8; 32],
    session_id: &str,
    client_id: &str,
) -> Result<String, String> {
    let storage_key = derive_storage_key(session_id, client_id)?;
    let cipher = Aes256Gcm::new_from_slice(&storage_key)
        .map_err(|e| format!("Storage key error: {}", e))?;

    let mut iv_bytes = [0u8; 12];
    getrandom::getrandom(&mut iv_bytes).map_err(|e| format!("RNG error: {}", e))?;
    let nonce = Nonce::from(iv_bytes);

    let ciphertext_with_tag = cipher
        .encrypt(&nonce, session_key.as_ref())
        .map_err(|e| format!("Storage encryption failed: {}", e))?;

    let mut result = Vec::with_capacity(12 + ciphertext_with_tag.len());
    result.extend_from_slice(&iv_bytes);
    result.extend_from_slice(&ciphertext_with_tag);

    Ok(B64.encode(&result))
}

fn decrypt_session_key_from_storage(
    ciphertext_b64: &str,
    session_id: &str,
    client_id: &str,
) -> Result<[u8; 32], String> {
    let encrypted = B64.decode(ciphertext_b64)
        .map_err(|e| format!("Base64 decode error: {}", e))?;
    if encrypted.len() < 28 {
        return Err("Encrypted session key too short".into());
    }

    let storage_key = derive_storage_key(session_id, client_id)?;
    let cipher = Aes256Gcm::new_from_slice(&storage_key)
        .map_err(|e| format!("Storage key error: {}", e))?;

    let nonce = Nonce::from(<[u8; 12]>::try_from(&encrypted[..12]).unwrap());
    let plaintext = cipher
        .decrypt(&nonce, &encrypted[12..])
        .map_err(|e| format!("Storage decryption failed: {}", e))?;

    if plaintext.len() != 32 {
        return Err("Invalid session key length".into());
    }

    let mut session_key = [0u8; 32];
    session_key.copy_from_slice(&plaintext);
    Ok(session_key)
}

// ═══════════════════════════════════════════════════════════════════════════
// TOKEN STORAGE ENCRYPTION
// ═══════════════════════════════════════════════════════════════════════════

fn store_token_to_storage(
    key: &str,
    token: &str,
    session_id: &str,
    client_id: &str,
) -> Result<(), JsValue> {
    let storage = get_session_storage()?;
    let storage_key = derive_storage_key(session_id, client_id)
        .map_err(|e| JsValue::from_str(&e))?;
    let encrypted = encrypt_aes_gcm(token, &storage_key, key.as_bytes())
        .map_err(|e| JsValue::from_str(&e))?;
    storage.set_item(key, &encrypted)?;
    Ok(())
}

fn load_token_from_storage(
    key: &str,
    session_id: &str,
    client_id: &str,
) -> Result<String, JsValue> {
    let storage = get_session_storage()?;
    let encrypted = storage.get_item(key)?
        .ok_or_else(|| JsValue::from_str(&format!("No {} found — run previous steps first", key)))?;
    let storage_key = derive_storage_key(session_id, client_id)
        .map_err(|e| JsValue::from_str(&e))?;
    decrypt_aes_gcm(&encrypted, &storage_key, key.as_bytes())
        .map_err(|e| JsValue::from_str(&e))
}

// ═══════════════════════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

fn get_session_storage() -> Result<Storage, JsValue> {
    window()
        .ok_or_else(|| JsValue::from_str("No window"))?
        .session_storage()?
        .ok_or_else(|| JsValue::from_str("No sessionStorage"))
}

fn log(msg: &str) {
    web_sys::console::log_1(&JsValue::from_str(msg));
}

#[wasm_bindgen]
pub fn generate_nonce() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[wasm_bindgen]
pub fn generate_timestamp() -> String {
    let date = js_sys::Date::new_0();
    date.to_iso_string().as_string().unwrap()
}

fn mask_tokens_in_json(json_str: &str) -> String {
    if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(json_str) {
        if let Some(obj) = value.as_object_mut() {
            for key in ["access_token", "refresh_token", "token"] {
                if obj.contains_key(key) {
                    obj.insert(
                        key.to_string(),
                        serde_json::Value::String("[PROTECTED_IN_WASM]".to_string()),
                    );
                }
            }
        }
        serde_json::to_string(&value).unwrap_or_else(|_| json_str.to_string())
    } else {
        json_str.to_string()
    }
}

fn parse_idempotency_key(key: &str) -> Result<(String, String), JsValue> {
    let parts: Vec<&str> = key.splitn(2, '.').collect();
    if parts.len() != 2 {
        return Err(JsValue::from_str("Invalid idempotency key format"));
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

async fn http_post(url: &str, body: &str, headers: &[(String, String)]) -> Result<String, JsValue> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;

    let opts = web_sys::RequestInit::new();
    opts.set_method("POST");
    opts.set_body(&JsValue::from_str(body));

    let request = web_sys::Request::new_with_str_and_init(url, &opts)?;
    let headers_obj = request.headers();
    for (k, v) in headers {
        headers_obj.set(k, v)?;
    }

    let window = web_sys::window().ok_or_else(|| JsValue::from_str("No window"))?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
    let resp: web_sys::Response = resp_value.dyn_into()?;

    if !resp.ok() {
        return Err(JsValue::from_str(&format!("HTTP {}", resp.status())));
    }

    let text = JsFuture::from(resp.text()?).await?;
    Ok(text.as_string().unwrap_or_default())
}

async fn http_post_with_headers(
    url: &str,
    body: &str,
    headers: &[(String, String)],
) -> Result<HttpResponseWithHeaders, JsValue> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;

    let opts = web_sys::RequestInit::new();
    opts.set_method("POST");
    opts.set_body(&JsValue::from_str(body));

    let request = web_sys::Request::new_with_str_and_init(url, &opts)?;
    let headers_obj = request.headers();
    for (k, v) in headers {
        headers_obj.set(k, v)?;
    }

    let window = web_sys::window().ok_or_else(|| JsValue::from_str("No window"))?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
    let resp: web_sys::Response = resp_value.dyn_into()?;

    if !resp.ok() {
        return Err(JsValue::from_str(&format!("HTTP {}", resp.status())));
    }

    let resp_headers = resp.headers();
    let idempotency_key = resp_headers.get("X-Idempotency-Key")?.unwrap_or_default();
    let kid = resp_headers.get("X-Kid")?.unwrap_or_default();
    let content_type = resp_headers.get("Content-Type")?.unwrap_or_default();

    let text = JsFuture::from(resp.text()?).await?;
    let body_text = text.as_string().unwrap_or_default();

    Ok(HttpResponseWithHeaders {
        body: body_text,
        idempotency_key,
        kid,
        content_type,
    })
}

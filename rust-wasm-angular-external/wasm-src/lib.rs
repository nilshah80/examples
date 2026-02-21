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
use wasm_bindgen::prelude::*;
use web_sys::{window, Storage};

type HmacSha256 = Hmac<Sha256>;

// ═══════════════════════════════════════════════════════════════════════════
// BUILD-TIME CONFIGURATION
// These values are injected at build time from environment variables
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
// STATIC WASM ENCRYPTION KEY
// This key is embedded in WASM binary and used ONLY to encrypt/decrypt
// the session key before storing in browser storage. This prevents the
// browser/JavaScript from ever seeing the plaintext session key.
// ═══════════════════════════════════════════════════════════════════════════

const WASM_STORAGE_KEY: [u8; 32] = [
    0x2a, 0x7b, 0x91, 0x4c, 0x65, 0xe8, 0x3f, 0xa9,
    0x1d, 0x52, 0xb3, 0x7e, 0x94, 0x0f, 0x6c, 0x28,
    0x83, 0xa4, 0x5d, 0x19, 0xf7, 0x2b, 0x68, 0x9a,
    0x3e, 0xd1, 0x4f, 0x86, 0x5c, 0x20, 0x97, 0xb5,
];

// ═══════════════════════════════════════════════════════════════════════════
// WASM BINDINGS - Configuration Getters
// ═══════════════════════════════════════════════════════════════════════════

/// Get sidecar URL from build-time config
#[wasm_bindgen]
pub fn get_sidecar_url() -> String {
    SIDECAR_URL.to_string()
}

/// Get client ID from build-time config
#[wasm_bindgen]
pub fn get_client_id() -> String {
    CLIENT_ID.to_string()
}

/// Get client secret from build-time config
#[wasm_bindgen]
pub fn get_client_secret() -> String {
    CLIENT_SECRET.to_string()
}

/// Get subject from build-time config
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
    /// Get session ID
    #[wasm_bindgen(getter)]
    pub fn session_id(&self) -> String {
        self.session_id.clone()
    }

    /// Get kid
    #[wasm_bindgen(getter)]
    pub fn kid(&self) -> String {
        self.kid.clone()
    }

    /// Get authenticated status
    #[wasm_bindgen(getter)]
    pub fn authenticated(&self) -> bool {
        self.authenticated
    }

    /// Get TTL
    #[wasm_bindgen(getter)]
    pub fn expires_in_sec(&self) -> i64 {
        self.expires_in_sec
    }

    /// Encrypt plaintext using session key
    #[wasm_bindgen]
    pub fn encrypt(&self, plaintext: &str, timestamp: &str, nonce: &str) -> Result<String, JsValue> {
        let aad = build_aad(timestamp, nonce, &self.kid, &self.client_id);
        encrypt_aes_gcm(plaintext, &self.session_key, &aad)
            .map_err(|e| JsValue::from_str(&e))
    }

    /// Decrypt ciphertext using session key
    #[wasm_bindgen]
    pub fn decrypt(&self, ciphertext: &str, timestamp: &str, nonce: &str) -> Result<String, JsValue> {
        let aad = build_aad(timestamp, nonce, &self.kid, &self.client_id);
        decrypt_aes_gcm(ciphertext, &self.session_key, &aad)
            .map_err(|e| JsValue::from_str(&e))
    }

    /// Save encrypted session key to sessionStorage
    /// The session key is encrypted with WASM_STORAGE_KEY before storing
    #[wasm_bindgen]
    pub fn save_to_storage(&self) -> Result<(), JsValue> {
        let storage = get_session_storage()?;

        // Encrypt session key with static WASM key
        let encrypted_session_key = encrypt_session_key_for_storage(&self.session_key)
            .map_err(|e| JsValue::from_str(&e))?;

        // Store metadata and encrypted session key
        storage.set_item("session_id", &self.session_id)?;
        storage.set_item("encrypted_session_key", &encrypted_session_key)?;
        storage.set_item("kid", &self.kid)?;
        storage.set_item("client_id", &self.client_id)?;
        storage.set_item("authenticated", &self.authenticated.to_string())?;
        storage.set_item("expires_in_sec", &self.expires_in_sec.to_string())?;

        log("Session saved to storage (session key encrypted with WASM key)");
        Ok(())
    }

    /// Load session from sessionStorage and decrypt session key
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

        // Decrypt session key using static WASM key
        let session_key = decrypt_session_key_from_storage(&encrypted_session_key)
            .map_err(|e| JsValue::from_str(&e))?;

        log("Session loaded from storage (session key decrypted with WASM key)");

        Ok(SessionContext {
            session_id,
            session_key,
            kid,
            client_id,
            authenticated,
            expires_in_sec,
        })
    }

    /// Clear session from storage
    #[wasm_bindgen]
    pub fn clear_storage() -> Result<(), JsValue> {
        let storage = get_session_storage()?;
        storage.remove_item("session_id")?;
        storage.remove_item("encrypted_session_key")?;
        storage.remove_item("kid")?;
        storage.remove_item("client_id")?;
        storage.remove_item("authenticated")?;
        storage.remove_item("expires_in_sec")?;
        log("Session cleared from storage");
        Ok(())
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

/// Initialize session with ECDH key exchange
/// Returns session context ready for encryption/decryption
#[wasm_bindgen]
pub async fn init_session(
    sidecar_url: &str,
    client_id: &str,
    access_token: Option<String>,
    subject: Option<String>,
) -> Result<SessionContext, JsValue> {
    // Generate ECDH keypair
    let secret = EphemeralSecret::random(&mut OsRng);
    let public_key = secret.public_key();
    let client_public_key_bytes = public_key.to_encoded_point(false);
    let client_public_key_b64 = B64.encode(client_public_key_bytes.as_bytes());

    // Prepare request
    let req_body = SessionInitRequest {
        client_public_key: client_public_key_b64,
    };
    let req_json = serde_json::to_string(&req_body)
        .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))?;

    // Build headers
    let mut headers = Vec::new();
    headers.push(("Content-Type".to_string(), "application/json".to_string()));
    headers.push(("X-ClientId".to_string(), client_id.to_string()));

    // Generate idempotency key
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

    // Call sidecar
    let url = format!("{}/api/v1/session/init", sidecar_url);
    let response = http_post(&url, &req_json, &headers).await?;

    let resp: SessionInitResponse = serde_json::from_str(&response)
        .map_err(|e| JsValue::from_str(&format!("JSON parse error: {}", e)))?;

    // Compute shared secret
    let peer_bytes = B64.decode(&resp.server_public_key)
        .map_err(|e| JsValue::from_str(&format!("Base64 decode error: {}", e)))?;
    let peer_point = EncodedPoint::from_bytes(&peer_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid EC point: {}", e)))?;
    let peer_public_key = Option::from(PublicKey::from_encoded_point(&peer_point))
        .ok_or_else(|| JsValue::from_str("Invalid peer public key"))?;
    let shared = secret.diffie_hellman(&peer_public_key);
    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(shared.raw_secret_bytes());

    // Derive session key via HKDF
    let session_key = derive_session_key(&mut shared_secret, &resp.session_id, client_id)
        .map_err(|e| JsValue::from_str(&e))?;

    // kid = "session:" + session_id
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

    // Zeroize shared secret
    shared_secret.fill(0);

    Ok(session_key)
}

fn encrypt_aes_gcm(plaintext: &str, key: &[u8; 32], aad: &[u8]) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("AES key error: {}", e))?;

    // Generate random 12-byte nonce
    let mut iv_bytes = [0u8; 12];
    getrandom::getrandom(&mut iv_bytes).map_err(|e| format!("RNG error: {}", e))?;
    let nonce = Nonce::from_slice(&iv_bytes);

    let payload = aes_gcm::aead::Payload {
        msg: plaintext.as_bytes(),
        aad,
    };

    let ciphertext_with_tag = cipher
        .encrypt(nonce, payload)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Assemble: IV(12) || ciphertext || tag(16)
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

    let nonce = Nonce::from_slice(&encrypted[..12]);
    let payload = aes_gcm::aead::Payload {
        msg: &encrypted[12..],
        aad,
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    String::from_utf8(plaintext).map_err(|e| format!("Invalid UTF-8: {}", e))
}

fn build_aad(timestamp: &str, nonce: &str, kid: &str, client_id: &str) -> Vec<u8> {
    format!("{}|{}|{}|{}", timestamp, nonce, kid, client_id).into_bytes()
}

// ═══════════════════════════════════════════════════════════════════════════
// SESSION KEY STORAGE ENCRYPTION
// Uses WASM_STORAGE_KEY to encrypt session key before storing in browser
// ═══════════════════════════════════════════════════════════════════════════

fn encrypt_session_key_for_storage(session_key: &[u8; 32]) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(&WASM_STORAGE_KEY)
        .map_err(|e| format!("Storage key error: {}", e))?;

    // Generate random 12-byte nonce
    let mut iv_bytes = [0u8; 12];
    getrandom::getrandom(&mut iv_bytes).map_err(|e| format!("RNG error: {}", e))?;
    let nonce = Nonce::from_slice(&iv_bytes);

    let ciphertext_with_tag = cipher
        .encrypt(nonce, session_key.as_ref())
        .map_err(|e| format!("Storage encryption failed: {}", e))?;

    // Assemble: IV(12) || ciphertext || tag(16)
    let mut result = Vec::with_capacity(12 + ciphertext_with_tag.len());
    result.extend_from_slice(&iv_bytes);
    result.extend_from_slice(&ciphertext_with_tag);

    Ok(B64.encode(&result))
}

fn decrypt_session_key_from_storage(ciphertext_b64: &str) -> Result<[u8; 32], String> {
    let encrypted = B64.decode(ciphertext_b64)
        .map_err(|e| format!("Base64 decode error: {}", e))?;
    if encrypted.len() < 28 {
        return Err("Encrypted session key too short".into());
    }

    let cipher = Aes256Gcm::new_from_slice(&WASM_STORAGE_KEY)
        .map_err(|e| format!("Storage key error: {}", e))?;

    let nonce = Nonce::from_slice(&encrypted[..12]);
    let plaintext = cipher
        .decrypt(nonce, &encrypted[12..])
        .map_err(|e| format!("Storage decryption failed: {}", e))?;

    if plaintext.len() != 32 {
        return Err("Invalid session key length".into());
    }

    let mut session_key = [0u8; 32];
    session_key.copy_from_slice(&plaintext);
    Ok(session_key)
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

/// Generate UUID v4 nonce
#[wasm_bindgen]
pub fn generate_nonce() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Generate ISO 8601 timestamp
#[wasm_bindgen]
pub fn generate_timestamp() -> String {
    let date = js_sys::Date::new_0();
    date.to_iso_string().as_string().unwrap()
}

/// Compute HMAC-SHA256 signature for external client authentication
///
/// This function is ONLY used for Step 2 (Token Issue) in external clients.
///
/// Algorithm:
/// 1. Compute SHA-256 hash of plaintext body (hex-encoded lowercase)
/// 2. Build string-to-sign: METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY_HASH
/// 3. Compute HMAC-SHA256(client_secret, string-to-sign)
/// 4. Return hex-encoded lowercase signature
///
/// # Arguments
/// * `method` - HTTP method in uppercase (e.g., "POST")
/// * `path` - API path (e.g., "/api/v1/token/issue")
/// * `timestamp` - Unix timestamp in milliseconds as string
/// * `nonce` - UUID v4 string
/// * `body` - Plaintext request body (BEFORE encryption)
/// * `secret` - Client secret from config
///
/// # Returns
/// Hex-encoded lowercase HMAC-SHA256 signature (64 characters)
#[wasm_bindgen]
pub fn compute_hmac_signature(
    method: &str,
    path: &str,
    timestamp: &str,
    nonce: &str,
    body: &str,
    secret: &str,
) -> String {
    // Step 1: Compute SHA-256 hash of plaintext body
    let body_hash = hex::encode(Sha256::digest(body.as_bytes()));

    // Step 2: Build string-to-sign with newline separators
    let string_to_sign = format!(
        "{}\n{}\n{}\n{}\n{}",
        method.to_uppercase(),
        path,
        timestamp,
        nonce,
        body_hash
    );

    // Step 3: Compute HMAC-SHA256 signature
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(string_to_sign.as_bytes());

    // Step 4: Hex-encode the signature (lowercase)
    hex::encode(mac.finalize().into_bytes())
}

/// Simple HTTP POST using fetch API
async fn http_post(url: &str, body: &str, headers: &[(String, String)]) -> Result<String, JsValue> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;

    let mut opts = web_sys::RequestInit::new();
    opts.method("POST");
    opts.body(Some(&JsValue::from_str(body)));

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

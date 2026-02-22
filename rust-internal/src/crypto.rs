use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey};
use sha2::Sha256;
use uuid::Uuid;

/// ECDH keypair holder. `secret` is consumed during shared secret computation.
pub struct EcdhKeyPair {
    pub secret: EphemeralSecret,
    pub public_key: PublicKey,
}

// ── Base64 ──────────────────────────────────────────────

pub fn to_base64(data: &[u8]) -> String {
    B64.encode(data)
}

pub fn from_base64(b64: &str) -> Result<Vec<u8>, base64::DecodeError> {
    B64.decode(b64)
}

// ── Nonce ───────────────────────────────────────────────

pub fn generate_nonce() -> String {
    Uuid::new_v4().to_string()
}

// ── ECDH P-256 ──────────────────────────────────────────

/// Generate an ECDH P-256 keypair.
pub fn generate_ecdh_keypair() -> EcdhKeyPair {
    let secret = EphemeralSecret::random(&mut OsRng);
    let public_key = secret.public_key();
    EcdhKeyPair { secret, public_key }
}

/// Export EC public key as 65-byte uncompressed: 0x04 || X(32) || Y(32).
pub fn export_public_key(key_pair: &EcdhKeyPair) -> Vec<u8> {
    let point = key_pair.public_key.to_encoded_point(false);
    point.as_bytes().to_vec()
}

/// Compute ECDH shared secret from our keypair and peer's 65-byte
/// uncompressed public key (base64-encoded). Consumes the secret key.
pub fn compute_shared_secret(
    key_pair: EcdhKeyPair,
    peer_public_key_base64: &str,
) -> Result<[u8; 32], String> {
    let peer_bytes = from_base64(peer_public_key_base64).map_err(|e| e.to_string())?;
    let peer_point =
        EncodedPoint::from_bytes(&peer_bytes).map_err(|e| format!("Invalid EC point: {e}"))?;
    let peer_public_key = Option::from(PublicKey::from_encoded_point(&peer_point))
        .ok_or("Invalid peer public key")?;
    let shared = key_pair.secret.diffie_hellman(&peer_public_key);
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.raw_secret_bytes());
    Ok(out)
}

// ── HKDF-SHA256 ─────────────────────────────────────────

/// HKDF-SHA256 key derivation.
/// salt = UTF-8(sessionId), info = UTF-8("SESSION|A256GCM|{clientId}")
pub fn derive_session_key(
    shared_secret: &mut [u8; 32],
    session_id: &str,
    client_id: &str,
) -> Result<[u8; 32], String> {
    let salt = session_id.as_bytes();
    let info = format!("SESSION|A256GCM|{client_id}");

    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut session_key = [0u8; 32];
    hk.expand(info.as_bytes(), &mut session_key)
        .map_err(|e| format!("HKDF expand failed: {e}"))?;

    // Zeroize shared secret
    shared_secret.fill(0);

    Ok(session_key)
}

// ── AES-256-GCM ─────────────────────────────────────────

/// AES-256-GCM encrypt.
/// Returns base64( IV(12) || ciphertext || tag(16) ).
pub fn encrypt(plaintext: &str, session_key: &[u8; 32], aad: &[u8]) -> Result<String, String> {
    let cipher =
        Aes256Gcm::new_from_slice(session_key).map_err(|e| format!("AES key error: {e}"))?;

    let iv_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from(iv_bytes);

    let payload = aes_gcm::aead::Payload {
        msg: plaintext.as_bytes(),
        aad,
    };

    let ciphertext_with_tag = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| format!("Encryption failed: {e}"))?;

    // Assemble: IV(12) || ciphertext || tag(16)
    // aes-gcm appends tag to ciphertext already
    let mut result = Vec::with_capacity(12 + ciphertext_with_tag.len());
    result.extend_from_slice(&iv_bytes);
    result.extend_from_slice(&ciphertext_with_tag);

    Ok(to_base64(&result))
}

/// AES-256-GCM decrypt.
/// Input: base64( IV(12) || ciphertext || tag(16) ).
pub fn decrypt(
    ciphertext_base64: &str,
    session_key: &[u8; 32],
    aad: &[u8],
) -> Result<String, String> {
    let encrypted = from_base64(ciphertext_base64).map_err(|e| e.to_string())?;
    if encrypted.len() < 28 {
        return Err("Ciphertext too short".into());
    }

    let cipher =
        Aes256Gcm::new_from_slice(session_key).map_err(|e| format!("AES key error: {e}"))?;

    let nonce = Nonce::from(<[u8; 12]>::try_from(&encrypted[..12]).unwrap());
    let payload = aes_gcm::aead::Payload {
        msg: &encrypted[12..],
        aad,
    };

    let plaintext = cipher
        .decrypt(&nonce, payload)
        .map_err(|e| format!("Decryption failed: {e}"))?;

    String::from_utf8(plaintext).map_err(|e| format!("Invalid UTF-8: {e}"))
}

// ── AAD ─────────────────────────────────────────────────

/// Build AAD: "timestamp|nonce|kid|clientId" as UTF-8 bytes.
pub fn build_aad(timestamp: &str, nonce: &str, kid: &str, client_id: &str) -> Vec<u8> {
    format!("{timestamp}|{nonce}|{kid}|{client_id}").into_bytes()
}

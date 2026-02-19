use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 signature for external client authentication.
///
/// 1. body_hash = SHA-256(plaintext).hex().lowercase()
/// 2. string_to_sign = "POST\n{path}\n{timestamp}\n{nonce}\n{body_hash}"
/// 3. signature = HMAC-SHA256(secret, string_to_sign).hex().lowercase()
pub fn compute_signature(
    method: &str,
    path: &str,
    timestamp: &str,
    nonce: &str,
    body: &str,
    secret: &str,
) -> String {
    // SHA-256 hash of the plaintext body
    let body_hash = hex::encode(Sha256::digest(body.as_bytes()));

    // Build string-to-sign
    let string_to_sign = format!(
        "{}\n{}\n{}\n{}\n{}",
        method.to_uppercase(),
        path,
        timestamp,
        nonce,
        body_hash
    );

    // HMAC-SHA256
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(string_to_sign.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

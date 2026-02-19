import hashlib
import hmac


def compute_signature(
    method: str, path: str, timestamp: str, nonce: str, body: str, secret: str
) -> str:
    """Compute HMAC-SHA256 signature for external client auth.

    1. bodyHash = SHA-256(body).hex().lowercase()
    2. stringToSign = "POST\\n{path}\\n{timestamp}\\n{nonce}\\n{bodyHash}"
    3. signature = HMAC-SHA256(secret, stringToSign).hex().lowercase()
    """
    body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    string_to_sign = f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{body_hash}"
    signature = hmac.new(
        secret.encode("utf-8"),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return signature

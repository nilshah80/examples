import base64
import os
import uuid

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization


# -- Base64 --

def to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def from_base64(b64: str) -> bytes:
    return base64.b64decode(b64)


# -- Nonce --

def generate_nonce() -> str:
    return str(uuid.uuid4())


# -- ECDH P-256 --

def generate_ecdh_keypair() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def export_public_key(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Export public key as 65-byte uncompressed: 0x04 || X(32) || Y(32)."""
    return private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )


def compute_shared_secret(
    private_key: ec.EllipticCurvePrivateKey,
    peer_public_key_base64: str,
) -> bytes:
    """Compute ECDH shared secret from our key and peer's base64 uncompressed public key."""
    peer_bytes = from_base64(peer_public_key_base64)
    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), peer_bytes
    )
    shared = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared  # 32 bytes for P-256


# -- HKDF-SHA256 --

def derive_session_key(
    shared_secret: bytes, session_id: str, client_id: str
) -> bytes:
    """HKDF-SHA256: salt=sessionId, info="SESSION|A256GCM|{clientId}", 32 bytes."""
    salt = session_id.encode("utf-8")
    info = f"SESSION|A256GCM|{client_id}".encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)


# -- AES-256-GCM --

def gcm_encrypt(plaintext: str, session_key: bytes, aad: bytes) -> str:
    """AES-256-GCM encrypt. Returns base64(IV(12) || ciphertext || tag(16))."""
    iv = os.urandom(12)
    aesgcm = AESGCM(session_key)
    ct_with_tag = aesgcm.encrypt(iv, plaintext.encode("utf-8"), aad)
    # ct_with_tag = ciphertext || tag(16)
    return to_base64(iv + ct_with_tag)


def gcm_decrypt(ciphertext_base64: str, session_key: bytes, aad: bytes) -> str:
    """AES-256-GCM decrypt. Input: base64(IV(12) || ciphertext || tag(16))."""
    encrypted = from_base64(ciphertext_base64)
    if len(encrypted) < 28:
        raise ValueError("Ciphertext too short")
    iv = encrypted[:12]
    ct_with_tag = encrypted[12:]
    aesgcm = AESGCM(session_key)
    plaintext = aesgcm.decrypt(iv, ct_with_tag, aad)
    return plaintext.decode("utf-8")


# -- AAD --

def build_aad(timestamp: str, nonce: str, kid: str, client_id: str) -> bytes:
    """Build AAD: "timestamp|nonce|kid|clientId" as UTF-8 bytes."""
    return f"{timestamp}|{nonce}|{kid}|{client_id}".encode("utf-8")

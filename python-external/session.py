import time

import requests

from config import Config
from crypto_utils import (
    compute_shared_secret,
    derive_session_key,
    export_public_key,
    generate_ecdh_keypair,
    generate_nonce,
    to_base64,
)
from models import SessionContext


def _millis_now() -> str:
    return str(int(time.time() * 1000))


def init_session(config: Config, http_client: requests.Session) -> SessionContext:
    """Step 1: Anonymous ECDH session init."""
    key_pair = generate_ecdh_keypair()
    pub_key_bytes = export_public_key(key_pair)
    nonce = generate_nonce()
    ts = _millis_now()

    body = {"clientPublicKey": to_base64(pub_key_bytes)}

    url = f"{config.sidecar_url}/api/v1/session/init"
    resp = http_client.post(
        url,
        json=body,
        headers={
            "Content-Type": "application/json",
            "X-Idempotency-Key": f"{ts}.{nonce}",
            "X-ClientId": config.client_id,
        },
    )

    if not resp.ok:
        raise RuntimeError(f"Session init failed: HTTP {resp.status_code} — {resp.text}")

    data = resp.json()
    return _derive_session(key_pair, data, config.client_id, False)


def refresh_session(
    config: Config,
    http_client: requests.Session,
    access_token: str,
    old_session: SessionContext | None,
) -> SessionContext:
    """Step 4: Authenticated session refresh with Bearer + X-Subject."""
    key_pair = generate_ecdh_keypair()
    pub_key_bytes = export_public_key(key_pair)
    nonce = generate_nonce()
    ts = _millis_now()

    body = {"clientPublicKey": to_base64(pub_key_bytes)}

    url = f"{config.sidecar_url}/api/v1/session/init"
    resp = http_client.post(
        url,
        json=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}",
            "X-Subject": config.subject,
            "X-Idempotency-Key": f"{ts}.{nonce}",
            "X-ClientId": config.client_id,
        },
    )

    # Zeroize old session key
    if old_session is not None:
        old_session.zeroize()

    if not resp.ok:
        raise RuntimeError(f"Session refresh failed: HTTP {resp.status_code} — {resp.text}")

    data = resp.json()
    return _derive_session(key_pair, data, config.client_id, True)


def _derive_session(key_pair, data: dict, client_id: str, authenticated: bool) -> SessionContext:
    shared = compute_shared_secret(key_pair, data["serverPublicKey"])
    session_key = derive_session_key(shared, data["sessionId"], client_id)

    return SessionContext(
        session_id=data["sessionId"],
        session_key=bytearray(session_key),
        kid=f"session:{data['sessionId']}",
        client_id=client_id,
        authenticated=authenticated,
        expires_in_sec=data["expiresInSec"],
    )

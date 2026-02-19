import json
import time

import requests as req_lib

from config import Config
from crypto_utils import build_aad, gcm_decrypt, gcm_encrypt, generate_nonce
from hmac_service import compute_signature
from models import SessionContext, StepResult


def _millis_now() -> str:
    return str(int(time.time() * 1000))


def issue_token(
    config: Config, http_client: req_lib.Session, session: SessionContext, plaintext: str
) -> StepResult:
    """Step 2: Token Issue (HMAC-SHA256 + GCM)."""
    start = time.time()

    nonce = generate_nonce()
    ts = _millis_now()
    aad = build_aad(ts, nonce, session.kid, session.client_id)

    try:
        encrypted = gcm_encrypt(plaintext, bytes(session.session_key), aad)
    except Exception as e:
        return _error_result(2, "Token Issue (HMAC-SHA256 + GCM)", plaintext, start, str(e))

    # Compute HMAC over PLAINTEXT body (before encryption)
    signature = compute_signature(
        "POST", "/api/v1/token/issue", ts, nonce, plaintext, config.client_secret,
    )

    headers = {
        "Content-Type": "application/json",
        "X-Kid": session.kid,
        "X-Idempotency-Key": f"{ts}.{nonce}",
        "X-ClientId": session.client_id,
        "X-Signature": signature,
    }

    request_body = json.dumps({"payload": encrypted})

    url = f"{config.sidecar_url}/api/v1/token/issue"
    try:
        resp = http_client.post(url, data=request_body, headers=headers)
    except Exception as e:
        return _error_result(2, "Token Issue (HMAC-SHA256 + GCM)", plaintext, start, str(e))

    resp_headers = _extract_response_headers(resp)
    response_body_str = resp.text

    # Attempt decryption even on error (sidecar encrypts error responses)
    resp_encrypted, decrypted = _decrypt_response(response_body_str, resp_headers, session)

    if not resp.ok:
        return StepResult(
            step=2, name="Token Issue (HMAC-SHA256 + GCM)",
            request_headers=headers, request_body_plaintext=plaintext,
            request_body_encrypted=encrypted, response_headers=resp_headers,
            response_body_encrypted=resp_encrypted, response_body_decrypted=decrypted,
            duration_ms=int((time.time() - start) * 1000),
            success=False, error=f"HTTP {resp.status_code}: {decrypted}",
        )

    return StepResult(
        step=2, name="Token Issue (HMAC-SHA256 + GCM)",
        request_headers=headers, request_body_plaintext=plaintext,
        request_body_encrypted=encrypted, response_headers=resp_headers,
        response_body_encrypted=resp_encrypted, response_body_decrypted=decrypted,
        duration_ms=int((time.time() - start) * 1000),
        success=True,
    )


def introspect_token(
    config: Config, http_client: req_lib.Session, session: SessionContext,
    plaintext: str, access_token: str,
) -> StepResult:
    """Step 3: Token Introspection (Bearer + GCM)."""
    auth = {"Authorization": f"Bearer {access_token}"}
    return _post_encrypted(
        config, http_client, "/v1/introspect", session, plaintext, auth,
        3, "Token Introspection (Bearer + GCM)",
    )


def refresh_token(
    config: Config, http_client: req_lib.Session, session: SessionContext,
    plaintext: str, access_token: str,
) -> StepResult:
    """Step 5: Token Refresh (Bearer + GCM)."""
    auth = {"Authorization": f"Bearer {access_token}"}
    return _post_encrypted(
        config, http_client, "/v1/token", session, plaintext, auth,
        5, "Token Refresh (Bearer + GCM)",
    )


def revoke_token(
    config: Config, http_client: req_lib.Session, session: SessionContext,
    plaintext: str, access_token: str,
) -> StepResult:
    """Step 6: Token Revocation (Bearer + GCM)."""
    auth = {"Authorization": f"Bearer {access_token}"}
    return _post_encrypted(
        config, http_client, "/v1/revoke", session, plaintext, auth,
        6, "Token Revocation (Bearer + GCM)",
    )


def _post_encrypted(
    config: Config, http_client: req_lib.Session, path: str,
    session: SessionContext, plaintext: str, auth_headers: dict,
    step_num: int, step_name: str,
) -> StepResult:
    start = time.time()

    nonce = generate_nonce()
    ts = _millis_now()
    aad = build_aad(ts, nonce, session.kid, session.client_id)

    try:
        encrypted = gcm_encrypt(plaintext, bytes(session.session_key), aad)
    except Exception as e:
        return _error_result(step_num, step_name, plaintext, start, str(e))

    headers = {
        "Content-Type": "application/json",
        "X-Kid": session.kid,
        "X-Idempotency-Key": f"{ts}.{nonce}",
        "X-ClientId": session.client_id,
    }
    headers.update(auth_headers)

    request_body = json.dumps({"payload": encrypted})

    url = f"{config.sidecar_url}/api{path}"
    try:
        resp = http_client.post(url, data=request_body, headers=headers)
    except Exception as e:
        return _error_result(step_num, step_name, plaintext, start, str(e))

    resp_headers = _extract_response_headers(resp)
    response_body_str = resp.text

    if not resp.ok:
        return StepResult(
            step=step_num, name=step_name,
            request_headers=headers, request_body_plaintext=plaintext,
            request_body_encrypted=encrypted, response_headers=resp_headers,
            response_body_encrypted="", response_body_decrypted=response_body_str,
            duration_ms=int((time.time() - start) * 1000),
            success=False, error=f"HTTP {resp.status_code}: {response_body_str}",
        )

    resp_encrypted, decrypted = _decrypt_response(response_body_str, resp_headers, session)

    return StepResult(
        step=step_num, name=step_name,
        request_headers=headers, request_body_plaintext=plaintext,
        request_body_encrypted=encrypted, response_headers=resp_headers,
        response_body_encrypted=resp_encrypted, response_body_decrypted=decrypted,
        duration_ms=int((time.time() - start) * 1000),
        success=True,
    )


def _decrypt_response(
    response_body: str, resp_headers: dict, session: SessionContext
) -> tuple[str, str]:
    resp_kid = resp_headers.get("x-kid")
    resp_idemp = resp_headers.get("x-idempotency-key")

    if resp_kid and resp_idemp:
        parts = resp_idemp.split(".", 1)
        if len(parts) == 2:
            resp_aad = build_aad(parts[0], parts[1], resp_kid, session.client_id)
            try:
                data = json.loads(response_body)
                if "payload" in data:
                    decrypted = gcm_decrypt(data["payload"], bytes(session.session_key), resp_aad)
                    return data["payload"], decrypted
            except Exception:
                pass

    return "", response_body


def _extract_response_headers(resp) -> dict:
    headers = {}
    for key in ["x-kid", "x-idempotency-key", "content-type"]:
        val = resp.headers.get(key)
        if val:
            headers[key] = val
    return headers


def _error_result(step_num: int, step_name: str, plaintext: str, start: float, error: str) -> StepResult:
    return StepResult(
        step=step_num, name=step_name,
        request_headers={}, request_body_plaintext=plaintext,
        request_body_encrypted="", response_headers={},
        response_body_encrypted="", response_body_decrypted="",
        duration_ms=int((time.time() - start) * 1000),
        success=False, error=error,
    )

from __future__ import annotations

import json
import sys
import time

from flask import Flask, jsonify, send_from_directory
import requests as req_lib

from config import load_config
from identity import introspect_token, issue_token, refresh_token, revoke_token
from models import SessionResult
from session import init_session, refresh_session

config = load_config()
http_client = req_lib.Session()

# Journey state
session_ctx = None
access_token = ""
refresh_token_val = ""

app = Flask(__name__, static_folder="static")


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/css/style.css")
def style():
    return send_from_directory("static/css", "style.css", mimetype="text/css")


@app.route("/steps/<int:n>", methods=["POST"])
def run_step(n: int):
    handlers = {1: step1, 2: step2, 3: step3, 4: step4, 5: step5, 6: step6}
    handler = handlers.get(n)
    if handler is None:
        return jsonify({"error": f"Invalid step {n}"}), 400
    return handler()


@app.route("/steps/reset", methods=["POST"])
def reset():
    global session_ctx, access_token, refresh_token_val
    if session_ctx is not None:
        session_ctx.zeroize()
    session_ctx = None
    access_token = ""
    refresh_token_val = ""
    return jsonify({"success": True})


def step1():
    global session_ctx, access_token, refresh_token_val
    start = time.time()
    try:
        session_ctx = init_session(config, http_client)
    except Exception as e:
        return jsonify(SessionResult(
            step=1, name="Session Init (Anonymous ECDH)",
            success=False, duration_ms=int((time.time() - start) * 1000),
            error=str(e),
        ).to_dict())
    access_token = ""
    refresh_token_val = ""
    return jsonify(SessionResult(
        step=1, name="Session Init (Anonymous ECDH)",
        success=True, duration_ms=int((time.time() - start) * 1000),
        session_id=session_ctx.session_id, kid=session_ctx.kid,
        authenticated=session_ctx.authenticated, expires_in_sec=session_ctx.expires_in_sec,
    ).to_dict())


def step2():
    global access_token, refresh_token_val
    if session_ctx is None:
        return jsonify({"error": "Run step 1 first"}), 400

    body = json.dumps({
        "audience": "orders-api",
        "scope": "orders.read orders.write",
        "subject": config.subject,
        "include_refresh_token": True,
        "single_session": True,
        "custom_claims": {
            "roles": "admin",
            "tenant": "test-corp",
        },
    })

    result = issue_token(config, http_client, session_ctx, body)

    if result.success:
        try:
            data = json.loads(result.response_body_decrypted)
            access_token = data.get("access_token", "")
            refresh_token_val = data.get("refresh_token", "")
        except Exception:
            pass

    return jsonify(result.to_dict())


def step3():
    if session_ctx is None or not access_token:
        return jsonify({"error": "Run steps 1-2 first"}), 400

    body = json.dumps({"token": access_token})
    result = introspect_token(config, http_client, session_ctx, body, access_token)
    return jsonify(result.to_dict())


def step4():
    global session_ctx
    if session_ctx is None or not access_token:
        return jsonify({"error": "Run steps 1-3 first"}), 400

    start = time.time()
    try:
        session_ctx = refresh_session(config, http_client, access_token, session_ctx)
    except Exception as e:
        return jsonify(SessionResult(
            step=4, name="Session Refresh (Authenticated ECDH)",
            success=False, duration_ms=int((time.time() - start) * 1000),
            error=str(e),
        ).to_dict())

    return jsonify(SessionResult(
        step=4, name="Session Refresh (Authenticated ECDH)",
        success=True, duration_ms=int((time.time() - start) * 1000),
        session_id=session_ctx.session_id, kid=session_ctx.kid,
        authenticated=session_ctx.authenticated, expires_in_sec=session_ctx.expires_in_sec,
    ).to_dict())


def step5():
    global access_token, refresh_token_val
    if session_ctx is None or not access_token:
        return jsonify({"error": "Run steps 1-4 first"}), 400

    body = json.dumps({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token_val,
    })
    result = refresh_token(config, http_client, session_ctx, body, access_token)

    if result.success:
        try:
            data = json.loads(result.response_body_decrypted)
            access_token = data.get("access_token", access_token)
            refresh_token_val = data.get("refresh_token", refresh_token_val)
        except Exception:
            pass

    return jsonify(result.to_dict())


def step6():
    if session_ctx is None or not access_token:
        return jsonify({"error": "Run steps 1-5 first"}), 400

    body = json.dumps({
        "token": refresh_token_val,
        "token_type_hint": "refresh_token",
    })
    result = revoke_token(config, http_client, session_ctx, body, access_token)
    return jsonify(result.to_dict())


# -- CLI Runner --

def run_cli():
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    BLUE = "\033[34m"
    GREEN = "\033[32m"
    RED = "\033[31m"
    CYAN = "\033[36m"
    YELLOW = "\033[33m"

    client_id = config.client_id

    print()
    print(f"{BLUE}{BOLD}  ╔══════════════════════════════════════════════════╗{RESET}")
    print(f"{BLUE}{BOLD}  ║  Identity Service — Internal Client (Python)     ║{RESET}")
    print(f"{BLUE}{BOLD}  ║  Auth: Basic Auth + AES-256-GCM                  ║{RESET}")
    print(f"{BLUE}{BOLD}  ║  Client: {client_id:<40} ║{RESET}")
    print(f"{BLUE}{BOLD}  ╚══════════════════════════════════════════════════╝{RESET}")
    print()

    def truncate(s: str, max_len: int = 200) -> str:
        if not s:
            return "(empty)"
        return s[:max_len] + "..." if len(s) > max_len else s

    def print_result(r):
        status = f"{GREEN}✓ Success" if r.success else f"{RED}✗ Failed"
        print(f"    {status} ({r.duration_ms}ms){RESET}")
        print(f"{YELLOW}    Request Body (plaintext):{RESET}")
        print(f"{DIM}      {truncate(r.request_body_plaintext)}{RESET}")
        print(f"{YELLOW}    Response Body (decrypted):{RESET}")
        print(f"{DIM}      {truncate(r.response_body_decrypted)}{RESET}")
        if not r.success and r.error:
            print(f"{RED}    Error: {r.error}{RESET}")
        print()

    cli_http = req_lib.Session()

    # Step 1: Session Init
    print(f"{CYAN}{BOLD}  ── Step 1: Session Init (Anonymous ECDH) ──{RESET}")
    try:
        sess = init_session(config, cli_http)
    except Exception as e:
        print(f"{RED}    ✗ {e}{RESET}")
        return
    auth_str = "authenticated" if sess.authenticated else "anonymous"
    print(f"{GREEN}    ✓ Session established{RESET}")
    print(f"{DIM}    SessionId: {sess.session_id}{RESET}")
    print(f"{DIM}    Kid:       {sess.kid}{RESET}")
    print(f"{DIM}    TTL:       {sess.expires_in_sec}s ({auth_str}){RESET}")
    print()

    # Step 2: Token Issue
    print(f"{CYAN}{BOLD}  ── Step 2: Token Issue (Basic Auth + GCM) ──{RESET}")
    issue_body = json.dumps({
        "audience": "orders-api",
        "scope": "orders.read orders.write",
        "subject": config.subject,
        "include_refresh_token": True,
        "single_session": True,
        "custom_claims": {"roles": "admin", "tenant": "test-corp"},
    })
    issue_result = issue_token(config, cli_http, sess, issue_body)
    print_result(issue_result)
    if not issue_result.success:
        return
    issue_data = json.loads(issue_result.response_body_decrypted)
    at = issue_data["access_token"]
    rt = issue_data.get("refresh_token", "")

    # Step 3: Token Introspection
    print(f"{CYAN}{BOLD}  ── Step 3: Token Introspection (Bearer + GCM) ──{RESET}")
    intro_body = json.dumps({"token": at})
    intro_result = introspect_token(config, cli_http, sess, intro_body, at)
    print_result(intro_result)
    if not intro_result.success:
        return

    # Step 4: Session Refresh
    print(f"{CYAN}{BOLD}  ── Step 4: Session Refresh (Authenticated ECDH) ──{RESET}")
    try:
        sess = refresh_session(config, cli_http, at, sess)
    except Exception as e:
        print(f"{RED}    ✗ {e}{RESET}")
        return
    print(f"{GREEN}    ✓ Session refreshed{RESET}")
    print(f"{DIM}    SessionId: {sess.session_id}{RESET}")
    print(f"{DIM}    TTL:       {sess.expires_in_sec}s (authenticated){RESET}")
    print()

    # Step 5: Token Refresh
    print(f"{CYAN}{BOLD}  ── Step 5: Token Refresh (Bearer + GCM) ──{RESET}")
    refresh_body = json.dumps({"grant_type": "refresh_token", "refresh_token": rt})
    refresh_result = refresh_token(config, cli_http, sess, refresh_body, at)
    print_result(refresh_result)
    if not refresh_result.success:
        return
    refresh_data = json.loads(refresh_result.response_body_decrypted)
    at = refresh_data["access_token"]
    rt = refresh_data.get("refresh_token", rt)

    # Step 6: Token Revocation
    print(f"{CYAN}{BOLD}  ── Step 6: Token Revocation (Bearer + GCM) ──{RESET}")
    revoke_body = json.dumps({"token": rt, "token_type_hint": "refresh_token"})
    revoke_result = revoke_token(config, cli_http, sess, revoke_body, at)
    print_result(revoke_result)

    # Cleanup
    sess.zeroize()
    print(f"{GREEN}{BOLD}  All 6 steps completed successfully!{RESET}")
    print()


if __name__ == "__main__":
    if "--cli" in sys.argv:
        run_cli()
    else:
        print()
        print("  Identity Service -- Internal Client Example (Python)")
        print(f"  Web UI:  http://localhost:{config.port}")
        print("  API:     /steps/1..6 -> Python crypto -> Sidecar")
        print("  Auth:    Basic Auth")
        print()
        app.run(host="0.0.0.0", port=config.port, debug=False)

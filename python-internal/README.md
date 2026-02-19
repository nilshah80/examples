# Identity Service — Internal Client Example (Python)

OAuth2 token lifecycle with AES-256-GCM encryption via the sidecar, authenticated using **HTTP Basic Auth**.

Python with Flask for the **Web UI** and a **CLI runner**, using the `cryptography` package (PyCA) for all crypto operations. Managed with `uv`.

## Prerequisites

- Python 3.9+ (uv manages its own Python)
- [uv](https://docs.astral.sh/uv/) package manager
- Identity Sidecar accessible (configured via `SIDECAR_URL` in `.env`)
- The `dev-client` client must exist in the database

## Quick Start

```bash
# Web UI mode
cd examples/python-internal
uv run python app.py
# Open http://localhost:3506

# CLI mode (terminal)
uv run python app.py --cli
```

## Client Configuration

| Field | Value |
|-------|-------|
| Client ID | `dev-client` |
| Client Secret | `DevSec-LwgT7vXGZk2njwglKWZBYW7q1sdNTElTQ!` |
| Auth Method | Basic Auth |
| Scopes | `orders.read orders.write` |
| Audience | `orders-api` |
| Subject | `test-user` |
| Server Port | `3506` |

> **Note**: The credentials above are **dummy values for testing only**. Replace them with your actual client ID and secret obtained from the Admin API. You can configure credentials via environment variables (`CLIENT_ID`, `CLIENT_SECRET`, `SUBJECT`) or in `.env`.

## Architecture

```
Browser (3506)  ──>  Flask endpoints  ──>  Sidecar  ──>  Identity API (8140)
     │                    │                       │                       │
     │  fetch('/steps/N') │  Python crypto         │  Decrypts GCM         │  Plaintext JSON
     │  Pure HTML          │  ECDH + HKDF + AES-GCM │  Forwards plaintext    │  Processes request
```

**Web UI**: Browser sends simple `fetch('/steps/N')` calls. All cryptography (ECDH, HKDF, AES-256-GCM) runs server-side in Python via `cryptography` (PyCA/OpenSSL).
**CLI**: Same Python crypto functions, colored ANSI output.

## Web UI API Endpoints

| Endpoint | Action |
|----------|--------|
| `POST /steps/1` | Session Init (Anonymous ECDH) |
| `POST /steps/2` | Token Issue (Basic Auth + GCM) |
| `POST /steps/3` | Token Introspection (Bearer + GCM) |
| `POST /steps/4` | Session Refresh (Authenticated ECDH) |
| `POST /steps/5` | Token Refresh (Bearer + GCM) |
| `POST /steps/6` | Token Revocation (Bearer + GCM) |
| `POST /steps/reset` | Reset journey state |

## 6-Step Journey

| Step | Sidecar Endpoint | Auth | Description |
|------|------------------|------|-------------|
| 1 | `POST /api/v1/session/init` | None | ECDH P-256 key exchange + HKDF-SHA256 key derivation |
| 2 | `POST /api/v1/token/issue` | Basic Auth + GCM | Issue access + refresh tokens |
| 3 | `POST /api/v1/introspect` | Bearer + GCM | Verify token is active, retrieve claims |
| 4 | `POST /api/v1/session/init` | Bearer + X-Subject | Authenticated session refresh (1hr TTL) |
| 5 | `POST /api/v1/token` | Bearer + GCM | Rotate tokens using refresh token |
| 6 | `POST /api/v1/revoke` | Bearer + GCM | Revoke refresh token (entire family) |

## Python Crypto Implementation

| Operation | Library / API |
|-----------|---------------|
| ECDH keypair | `ec.generate_private_key(ec.SECP256R1())` |
| Export public key | `public_bytes(Encoding.X962, UncompressedPoint)` — 65 bytes |
| ECDH shared secret | `private_key.exchange(ec.ECDH(), peer_public_key)` |
| HKDF-SHA256 | `cryptography.hazmat.primitives.kdf.hkdf.HKDF` |
| AES-256-GCM | `cryptography.hazmat.primitives.ciphers.aead.AESGCM` + 12-byte IV |
| Zeroize | Manual `bytearray` zeroing |

## Dependencies

| Package | Purpose |
|---------|---------|
| `flask` | Lightweight web server |
| `cryptography` | ECDH P-256, HKDF-SHA256, AES-256-GCM (wraps OpenSSL) |
| `requests` | HTTP client for sidecar API calls |
| `python-dotenv` | `.env` file loading |

## File Structure

```
python-internal/
├── pyproject.toml             uv project config + dependencies
├── uv.lock                    Dependency lock file
├── .env / .env.example        Environment configuration
├── app.py                     Entry point: Flask server + CLI runner
├── config.py                  Env loading (python-dotenv)
├── crypto_utils.py            ECDH P-256, HKDF-SHA256, AES-256-GCM
├── models.py                  SessionContext, StepResult, SessionResult
├── session.py                 Session init + refresh
├── identity.py                Token ops (Basic Auth + GCM)
├── static/
│   ├── index.html             Web UI (pure HTML + fetch to /steps)
│   └── css/style.css          Dark theme (blue accent)
└── README.md
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `Failed to fetch` | Python app not running | Run `uv run python app.py` first |
| 502 Bad Gateway | Sidecar not running | Start sidecar or verify `SIDECAR_URL` |
| 401 Unauthorized | Wrong credentials | Verify `dev-client` exists with correct secret |
| Connection refused (CLI) | Sidecar unreachable | Verify `SIDECAR_URL` and sidecar availability |
| `ModuleNotFoundError` | Dependencies not installed | Run `uv sync` to install dependencies |

# Identity Service — External Client Example (Python)

OAuth2 token lifecycle with AES-256-GCM encryption via the sidecar, authenticated using **HMAC-SHA256** signatures.

Python with Flask for the **Web UI** and a **CLI runner**, using the `cryptography` package (PyCA) for all crypto operations. Managed with `uv`.

## Prerequisites

- Python 3.9+ (uv manages its own Python)
- [uv](https://docs.astral.sh/uv/) package manager
- Identity Sidecar accessible (configured via `SIDECAR_URL` in `.env`)
- The `external-partner-test` client must exist in the database

## Quick Start

```bash
# Web UI mode
cd examples/python-external
uv run python app.py
# Open http://localhost:3507

# CLI mode (terminal)
uv run python app.py --cli
```

## Client Configuration

| Field | Value |
|-------|-------|
| Client ID | `external-partner-test` |
| Client Secret | `external-partner-hmac-secret-key-32chars!` |
| Auth Method | HMAC-SHA256 (X-Signature) |
| Scopes | `orders.read` |
| Audience | `orders-api` |
| Subject | `hmac-user` |
| Server Port | `3507` |

> **Note**: The credentials above are **dummy values for testing only**. Replace them with your actual client ID and secret obtained from the Admin API. You can configure credentials via environment variables (`CLIENT_ID`, `CLIENT_SECRET`, `SUBJECT`) or in `.env`.

## Architecture

```
Browser (3507)  ──>  Flask endpoints  ──>  Sidecar  ──>  Identity API (8140)
     │                    │                       │                       │
     │  fetch('/steps/N') │  Python crypto         │  Decrypts GCM         │  Plaintext JSON
     │  Pure HTML          │  ECDH + HKDF + AES-GCM │  Forwards plaintext    │  Processes request
```

**Web UI**: Browser sends simple `fetch('/steps/N')` calls. All cryptography (ECDH, HKDF, AES-256-GCM, HMAC-SHA256) runs server-side in Python via `cryptography` (PyCA/OpenSSL).
**CLI**: Same Python crypto functions, colored ANSI output.

## Web UI API Endpoints

| Endpoint | Action |
|----------|--------|
| `POST /steps/1` | Session Init (Anonymous ECDH) |
| `POST /steps/2` | Token Issue (HMAC-SHA256 + GCM) |
| `POST /steps/3` | Token Introspection (Bearer + GCM) |
| `POST /steps/4` | Session Refresh (Authenticated ECDH) |
| `POST /steps/5` | Token Refresh (Bearer + GCM) |
| `POST /steps/6` | Token Revocation (Bearer + GCM) |
| `POST /steps/reset` | Reset journey state |

## 6-Step Journey

| Step | Sidecar Endpoint | Auth | Description |
|------|------------------|------|-------------|
| 1 | `POST /api/v1/session/init` | None | ECDH P-256 key exchange + HKDF-SHA256 key derivation |
| 2 | `POST /api/v1/token/issue` | HMAC-SHA256 + GCM | Issue access + refresh tokens (X-Signature header) |
| 3 | `POST /api/v1/introspect` | Bearer + GCM | Verify token is active, retrieve claims |
| 4 | `POST /api/v1/session/init` | Bearer + X-Subject | Authenticated session refresh (1hr TTL) |
| 5 | `POST /api/v1/token` | Bearer + GCM | Rotate tokens using refresh token |
| 6 | `POST /api/v1/revoke` | Bearer + GCM | Revoke refresh token (entire family) |

## HMAC-SHA256 Signature

External clients authenticate token issuance using HMAC-SHA256:

```
bodyHash     = SHA-256(plaintextBody).hex()
stringToSign = "POST\n/api/v1/token/issue\n{timestamp}\n{nonce}\n{bodyHash}"
signature    = HMAC-SHA256(clientSecret, stringToSign).hex()
```

The signature is sent in the `X-Signature` header. HMAC is computed over the **plaintext** body (before GCM encryption).

## Python Crypto Implementation

| Operation | Library / API |
|-----------|---------------|
| ECDH keypair | `ec.generate_private_key(ec.SECP256R1())` |
| Export public key | `public_bytes(Encoding.X962, UncompressedPoint)` — 65 bytes |
| ECDH shared secret | `private_key.exchange(ec.ECDH(), peer_public_key)` |
| HKDF-SHA256 | `cryptography.hazmat.primitives.kdf.hkdf.HKDF` |
| AES-256-GCM | `cryptography.hazmat.primitives.ciphers.aead.AESGCM` + 12-byte IV |
| SHA-256 | `hashlib.sha256()` |
| HMAC-SHA256 | `hmac.new(key, msg, hashlib.sha256)` |
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
python-external/
├── pyproject.toml             uv project config + dependencies
├── uv.lock                    Dependency lock file
├── .env / .env.example        Environment configuration
├── app.py                     Entry point: Flask server + CLI runner
├── config.py                  Env loading (python-dotenv)
├── crypto_utils.py            ECDH P-256, HKDF-SHA256, AES-256-GCM
├── hmac_service.py            HMAC-SHA256 signature computation
├── models.py                  SessionContext, StepResult, SessionResult
├── session.py                 Session init + refresh
├── identity.py                Token ops (HMAC + GCM for issue, Bearer for rest)
├── static/
│   ├── index.html             Web UI (pure HTML + fetch to /steps)
│   └── css/style.css          Dark theme (amber accent)
└── README.md
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `Failed to fetch` | Python app not running | Run `uv run python app.py` first |
| 502 Bad Gateway | Sidecar not running | Start sidecar or verify `SIDECAR_URL` |
| 401 Unauthorized | Wrong credentials or invalid HMAC | Verify `external-partner-test` exists with correct secret |
| Connection refused (CLI) | Sidecar unreachable | Verify `SIDECAR_URL` and sidecar availability |
| `ModuleNotFoundError` | Dependencies not installed | Run `uv sync` to install dependencies |

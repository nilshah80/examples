# Identity Service — External Client Example (Rust)

OAuth2 token lifecycle with AES-256-GCM encryption via the sidecar, authenticated using **HMAC-SHA256** signatures.

Rust with Actix-web for the **Web UI** and a **CLI runner**, using `ring` and `p256` crates for cryptography.

## Prerequisites

- Rust toolchain (rustc/cargo)
- Identity Sidecar accessible (configured via `SIDECAR_URL` in `.env`)
- The `external-partner-test` client must exist in the database

## Quick Start

```bash
# Web UI mode
cd examples/rust-external
cargo run --release
# Open http://localhost:3503

# CLI mode (terminal)
cargo run --release -- --cli
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
| Server Port | `3503` |

> **Note**: The credentials above are **dummy values for testing only**. Replace them with your actual client ID and secret obtained from the Admin API. You can configure credentials via environment variables (`CLIENT_ID`, `CLIENT_SECRET`, `SUBJECT`) or in `.env`.

## Architecture

```
Browser (3503)  ──>  Actix-web endpoints  ──>  Sidecar  ──>  Identity API (8140)
     │                    │                       │                       │
     │  fetch('/steps/N') │  Rust crypto           │  Decrypts GCM         │  Plaintext JSON
     │  Pure HTML          │  ECDH + HKDF + AES-GCM │  Forwards plaintext    │  Processes request
```

**Web UI**: Browser sends simple `fetch('/steps/N')` calls. All cryptography (ECDH, HKDF, AES-256-GCM, HMAC-SHA256) runs server-side in Rust.
**CLI**: Same Rust crypto functions, colored ANSI output.

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

## Rust Crypto Implementation

| Operation | Crate / API |
|-----------|-------------|
| ECDH keypair | `p256::ecdh::EphemeralSecret` + `p256::EncodedPoint` |
| ECDH shared secret | `EphemeralSecret::diffie_hellman()` |
| HKDF-SHA256 | `ring::hkdf` (salt=sessionId, info="SESSION\|A256GCM\|{clientId}") |
| AES-256-GCM | `ring::aead::AES_256_GCM` + 12-byte nonce |
| SHA-256 | `ring::digest::SHA256` |
| HMAC-SHA256 | `ring::hmac::sign(HMAC_SHA256, key, data)` |
| Zeroize | `zeroize::Zeroize` trait |

## File Structure

```
rust-external/
├── Cargo.toml                 Dependencies: actix-web, p256, ring, reqwest, serde, dotenv
├── src/
│   ├── main.rs                Entry point: Actix-web server + CLI runner
│   ├── config.rs              Env loading (dotenv)
│   ├── crypto.rs              ECDH P-256, HKDF-SHA256, AES-256-GCM
│   ├── hmac_service.rs        HMAC-SHA256 signature computation
│   ├── models.rs              SessionContext, StepResult, SessionResult
│   ├── session.rs             Session init + refresh
│   └── identity.rs            Token ops (HMAC + GCM for issue, Bearer for rest)
├── static/
│   ├── index.html             Web UI (pure HTML + fetch to /steps)
│   └── css/style.css          Dark theme (amber accent)
└── README.md
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `Failed to fetch` | Rust app not running | Run `cargo run --release` first |
| 502 Bad Gateway | Sidecar not running | Start sidecar or verify `SIDECAR_URL` |
| 401 Unauthorized | Wrong credentials or invalid HMAC | Verify `external-partner-test` exists with correct secret |
| Connection refused (CLI) | Sidecar unreachable | Verify `SIDECAR_URL` and sidecar availability |

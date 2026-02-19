# Identity Service — External Client Example (Go)

OAuth2 token lifecycle with AES-256-GCM encryption via the sidecar, authenticated using **HMAC-SHA256** signatures.

Go with `net/http` stdlib for the **Web UI** and a **CLI runner**. Crypto uses `crypto/ecdh`, `crypto/aes`, `crypto/cipher`, `crypto/hmac`, and `golang.org/x/crypto/hkdf`.

## Prerequisites

- Go 1.21+ (uses `crypto/ecdh` introduced in Go 1.20)
- Identity Sidecar accessible (configured via `SIDECAR_URL` in `.env`)
- The `external-partner-test` client must exist in the database

## Quick Start

```bash
# Web UI mode
cd examples/go-external
go run .
# Open http://localhost:3505

# CLI mode (terminal)
go run . --cli
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
| Server Port | `3505` |

> **Note**: The credentials above are **dummy values for testing only**. Replace them with your actual client ID and secret obtained from the Admin API. You can configure credentials via environment variables (`CLIENT_ID`, `CLIENT_SECRET`, `SUBJECT`) or in `.env`.

## Architecture

```
Browser (3505)  ──>  net/http endpoints  ──>  Sidecar  ──>  Identity API (8140)
     │                    │                       │                       │
     │  fetch('/steps/N') │  Go crypto             │  Decrypts GCM         │  Plaintext JSON
     │  Pure HTML          │  ECDH + HKDF + AES-GCM │  Forwards plaintext    │  Processes request
```

**Web UI**: Browser sends simple `fetch('/steps/N')` calls. All cryptography (ECDH, HKDF, AES-256-GCM, HMAC-SHA256) runs server-side in Go. Static files are embedded via `//go:embed`.
**CLI**: Same Go crypto functions, colored ANSI output.

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

## Go Crypto Implementation

| Operation | Go API |
|-----------|--------|
| ECDH keypair | `ecdh.P256().GenerateKey(rand.Reader)` |
| ECDH shared secret | `privateKey.ECDH(peerPublicKey)` |
| HKDF-SHA256 | `hkdf.New(sha256.New, ikm, salt, info)` |
| AES-256-GCM | `aes.NewCipher(key)` + `cipher.NewGCM(block)` + 12-byte nonce |
| SHA-256 | `crypto/sha256.Sum256(data)` |
| HMAC-SHA256 | `hmac.New(sha256.New, key)` |
| Zeroize | Manual `for i := range key { key[i] = 0 }` |

## Dependencies

Only 3 external dependencies (everything else is stdlib):

| Module | Purpose |
|--------|---------|
| `golang.org/x/crypto` | HKDF implementation |
| `github.com/joho/godotenv` | `.env` file loading |
| `github.com/google/uuid` | UUID v4 nonce generation |

## File Structure

```
go-external/
├── go.mod                     Module definition + dependencies
├── go.sum                     Dependency checksums
├── main.go                    Entry point: net/http server + CLI runner
├── config.go                  Env loading (godotenv)
├── crypto.go                  ECDH P-256, HKDF-SHA256, AES-256-GCM
├── hmac_service.go            HMAC-SHA256 signature computation
├── models.go                  SessionContext, StepResult, SessionResult
├── session.go                 Session init + refresh
├── identity.go                Token ops (HMAC + GCM for issue, Bearer for rest)
├── static/
│   ├── index.html             Web UI (embedded via go:embed)
│   └── css/style.css          Dark theme (amber accent)
└── README.md
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `Failed to fetch` | Go app not running | Run `go run .` first |
| 502 Bad Gateway | Sidecar not running | Start sidecar or verify `SIDECAR_URL` |
| 401 Unauthorized | Wrong credentials or invalid HMAC | Verify `external-partner-test` exists with correct secret |
| Connection refused (CLI) | Sidecar unreachable | Verify `SIDECAR_URL` and sidecar availability |

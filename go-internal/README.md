# Identity Service — Internal Client Example (Go)

OAuth2 token lifecycle with AES-256-GCM encryption via the sidecar, authenticated using **HTTP Basic Auth**.

Go with `net/http` stdlib for the **Web UI** and a **CLI runner**. Crypto uses `crypto/ecdh`, `crypto/aes`, `crypto/cipher`, and `golang.org/x/crypto/hkdf`.

## Prerequisites

- Go 1.21+ (uses `crypto/ecdh` introduced in Go 1.20)
- Identity Sidecar accessible (configured via `SIDECAR_URL` in `.env`)
- The `dev-client` client must exist in the database

## Quick Start

```bash
# Web UI mode
cd examples/go-internal
go run .
# Open http://localhost:3504

# CLI mode (terminal)
go run . --cli
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
| Server Port | `3504` |

> **Note**: The credentials above are **dummy values for testing only**. Replace them with your actual client ID and secret obtained from the Admin API. You can configure credentials via environment variables (`CLIENT_ID`, `CLIENT_SECRET`, `SUBJECT`) or in `.env`.

## Architecture

```
Browser (3504)  ──>  net/http endpoints  ──>  Sidecar  ──>  Identity API (8140)
     │                    │                       │                       │
     │  fetch('/steps/N') │  Go crypto             │  Decrypts GCM         │  Plaintext JSON
     │  Pure HTML          │  ECDH + HKDF + AES-GCM │  Forwards plaintext    │  Processes request
```

**Web UI**: Browser sends simple `fetch('/steps/N')` calls. All cryptography (ECDH, HKDF, AES-256-GCM) runs server-side in Go. Static files are embedded via `//go:embed`.
**CLI**: Same Go crypto functions, colored ANSI output.

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

## Go Crypto Implementation

| Operation | Go API |
|-----------|--------|
| ECDH keypair | `ecdh.P256().GenerateKey(rand.Reader)` |
| ECDH shared secret | `privateKey.ECDH(peerPublicKey)` |
| HKDF-SHA256 | `hkdf.New(sha256.New, ikm, salt, info)` |
| AES-256-GCM | `aes.NewCipher(key)` + `cipher.NewGCM(block)` + 12-byte nonce |
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
go-internal/
├── go.mod                     Module definition + dependencies
├── go.sum                     Dependency checksums
├── main.go                    Entry point: net/http server + CLI runner
├── config.go                  Env loading (godotenv)
├── crypto.go                  ECDH P-256, HKDF-SHA256, AES-256-GCM
├── models.go                  SessionContext, StepResult, SessionResult
├── session.go                 Session init + refresh
├── identity.go                Token ops (Basic Auth + GCM)
├── static/
│   ├── index.html             Web UI (embedded via go:embed)
│   └── css/style.css          Dark theme (blue accent)
└── README.md
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `Failed to fetch` | Go app not running | Run `go run .` first |
| 502 Bad Gateway | Sidecar not running | Start sidecar or verify `SIDECAR_URL` |
| 401 Unauthorized | Wrong credentials | Verify `dev-client` exists with correct secret |
| Connection refused (CLI) | Sidecar unreachable | Verify `SIDECAR_URL` and sidecar availability |

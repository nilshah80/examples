# Identity Service — Internal Client Example (.NET 8)

OAuth2 token lifecycle with AES-256-GCM encryption via the sidecar, authenticated using **HTTP Basic Auth**.

.NET 8 Minimal API with both a **Web UI** (server-side .NET crypto) and a **CLI runner** (System.Security.Cryptography).

## Prerequisites

- .NET 8 SDK
- Identity Sidecar accessible (configured via `SIDECAR_URL` in `.env`)
- The `dev-client` client must exist in the database

## Quick Start

```bash
# Web UI mode
cd examples/dotnet-internal
dotnet run
# Open http://localhost:3500

# CLI mode (terminal)
dotnet run -- --cli
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
| Server Port | `3500` |

> **Note**: The credentials above are **dummy values for testing only**. Replace them with your actual client ID and secret obtained from the Admin API. You can configure credentials via environment variables (`CLIENT_ID`, `CLIENT_SECRET`, `SUBJECT`) or in `appsettings.json`.

## Architecture

```
Browser (3500)  ──>  .NET API endpoints  ──>  Sidecar  ──>  Identity API (8140)
     │                    │                       │                       │
     │  fetch('/steps/N') │  .NET crypto           │  Decrypts GCM         │  Plaintext JSON
     │  Pure HTML          │  ECDH + HKDF + AES-GCM │  Forwards plaintext    │  Processes request
```

**Web UI**: Browser sends simple `fetch('/steps/N')` calls. All cryptography (ECDH, HKDF, AES-256-GCM) runs server-side in .NET.
**CLI**: Same .NET services handle crypto via `System.Security.Cryptography`.

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

## .NET Crypto Implementation

| Operation | .NET API |
|-----------|----------|
| ECDH keypair | `ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256)` |
| ECDH shared secret | `DeriveRawSecretAgreement(peerKey.PublicKey)` |
| HKDF-SHA256 | `HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, length, salt, info)` |
| AES-256-GCM | `new AesGcm(key, tagSizeInBytes: 16)` + 12-byte nonce |
| Zeroize | `CryptographicOperations.ZeroMemory(span)` |

## File Structure

```
dotnet-internal/
├── DotnetInternal.csproj               .NET 8 Web SDK (zero NuGet deps)
├── Program.cs                          Entry point: /steps API + CLI runner
├── appsettings.json                    Port, sidecar URL, client credentials
├── Models/
│   ├── SessionContext.cs               ECDH session state
│   ├── StepResult.cs                   Step execution result
│   └── ApiModels.cs                    Request/response DTOs
├── Services/
│   ├── CryptoService.cs                ECDH P-256, HKDF-SHA256, AES-256-GCM
│   ├── SessionService.cs               Session init + refresh
│   └── IdentityService.cs              Token ops (Basic Auth + GCM)
├── wwwroot/
│   ├── index.html                      Web UI (pure HTML + fetch to /steps)
│   └── css/style.css                   Dark theme (blue accent)
└── README.md
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `Failed to fetch` | .NET app not running | Run `dotnet run` first |
| 502 Bad Gateway | Sidecar not running | Start sidecar or verify `SIDECAR_URL` |
| 401 Unauthorized | Wrong credentials | Verify `dev-client` exists with correct secret |
| Connection refused (CLI) | Sidecar unreachable | Verify `SIDECAR_URL` and sidecar availability |
| `PlatformNotSupportedException` | AES-GCM not supported | Use .NET 8+ on a supported OS |

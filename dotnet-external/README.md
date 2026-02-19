# Identity Service — External Client Example (.NET 8)

OAuth2 token lifecycle with AES-256-GCM encryption via the sidecar, authenticated using **HMAC-SHA256** signatures.

.NET 8 Minimal API with both a **Web UI** (server-side .NET crypto) and a **CLI runner** (System.Security.Cryptography).

## Prerequisites

- .NET 8 SDK
- Identity Sidecar accessible (configured via `SIDECAR_URL` in `.env`)
- The `external-partner-test` client must exist in the database

## Quick Start

```bash
# Web UI mode
cd examples/dotnet-external
dotnet run
# Open http://localhost:3501

# CLI mode (terminal)
dotnet run -- --cli
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
| Server Port | `3501` |

> **Note**: The credentials above are **dummy values for testing only**. Replace them with your actual client ID and secret obtained from the Admin API. You can configure credentials via environment variables (`CLIENT_ID`, `CLIENT_SECRET`, `SUBJECT`) or in `appsettings.json`.

## Architecture

```
Browser (3501)  ──>  .NET API endpoints  ──>  Sidecar  ──>  Identity API (8140)
     │                    │                       │                       │
     │  fetch('/steps/N') │  .NET crypto           │  Decrypts GCM         │  Plaintext JSON
     │  Pure HTML          │  ECDH + HKDF + AES-GCM │  Forwards plaintext    │  Processes request
```

**Web UI**: Browser sends simple `fetch('/steps/N')` calls. All cryptography (ECDH, HKDF, AES-256-GCM, HMAC-SHA256) runs server-side in .NET.
**CLI**: Same .NET services handle crypto via `System.Security.Cryptography`.

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

## .NET Crypto Implementation

| Operation | .NET API |
|-----------|----------|
| ECDH keypair | `ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256)` |
| ECDH shared secret | `DeriveRawSecretAgreement(peerKey.PublicKey)` |
| HKDF-SHA256 | `HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, length, salt, info)` |
| AES-256-GCM | `new AesGcm(key, tagSizeInBytes: 16)` + 12-byte nonce |
| SHA-256 | `SHA256.HashData(data)` |
| HMAC-SHA256 | `new HMACSHA256(key).ComputeHash(data)` |
| Hex encode | `Convert.ToHexStringLower()` |
| Zeroize | `CryptographicOperations.ZeroMemory(span)` |

## File Structure

```
dotnet-external/
├── DotnetExternal.csproj               .NET 8 Web SDK (zero NuGet deps)
├── Program.cs                          Entry point: /steps API + CLI runner
├── appsettings.json                    Port, sidecar URL, client credentials
├── Models/
│   ├── SessionContext.cs               ECDH session state
│   ├── StepResult.cs                   Step execution result
│   └── ApiModels.cs                    Request/response DTOs
├── Services/
│   ├── CryptoService.cs                ECDH P-256, HKDF-SHA256, AES-256-GCM
│   ├── HmacService.cs                  HMAC-SHA256 signature computation
│   ├── SessionService.cs               Session init + refresh
│   └── IdentityService.cs              Token ops (HMAC + GCM for issue, Bearer for rest)
├── wwwroot/
│   ├── index.html                      Web UI (pure HTML + fetch to /steps)
│   └── css/style.css                   Dark theme (amber accent)
└── README.md
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `Failed to fetch` | .NET app not running | Run `dotnet run` first |
| 502 Bad Gateway | Sidecar not running | Start sidecar or verify `SIDECAR_URL` |
| 401 Unauthorized | Wrong credentials or invalid HMAC | Verify `external-partner-test` exists with correct secret |
| Connection refused (CLI) | Sidecar unreachable | Verify `SIDECAR_URL` and sidecar availability |
| `PlatformNotSupportedException` | AES-GCM not supported | Use .NET 8+ on a supported OS |

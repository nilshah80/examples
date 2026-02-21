# Identity Service — Rust WASM Example (External Client)

OAuth2 token lifecycle with HMAC-SHA256 authentication and AES-256-GCM encryption running entirely in **WebAssembly**.

**Client Type:** External Client (HMAC-SHA256) — similar to `rust-external`, `go-external`

**Key Security Features:**
- **HMAC-SHA256 signature** computed in WASM for Step 2 (Token Issue) authentication
- **Static encryption key embedded in WASM** encrypts the session key before storing it in `sessionStorage`
- JavaScript and browser developer tools can **only see the encrypted session key**, never the plaintext

## What Makes This "External"?

**Step 2 (Token Issue) Authentication:**
- **External Client:** Uses `X-Signature` header with HMAC-SHA256 signature
- **Internal Client:** Uses `Authorization: Basic` header

**All other steps (1, 3, 4, 5, 6):** Identical to internal client (Bearer token or anonymous)

## Prerequisites

- Rust toolchain (rustc/cargo)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) for building WASM
- Node.js (for CORS proxy)
- Identity Sidecar accessible
- The `external-client-1` client must exist in the database

## Client Configuration

| Field | Value |
|-------|-------|
| Client ID | `external-client-1` |
| Client Secret | `ExtSec-KjH8vN2mPqW5xYzA3bC6dE9fG1hI4jK7lM0nO!` |
| Auth Method | HMAC-SHA256 (X-Signature header for Step 2 only) |
| Scopes | `orders.read orders.write` |
| Audience | `orders-api` |
| Subject | `test-user` |

> **Note**: Configuration is **injected at build time** from [.env](.env) file into the WASM binary.

## Quick Start

```bash
cd examples/rust-wasm-external

# 1. Configure (edit .env file)
#    Make sure to use CLIENT_ID=external-client-1
vim .env

# 2. Build WASM module
./build.sh

# 3. Start CORS proxy server
node proxy-server.js

# 4. Open browser
open http://localhost:8080
```

## HMAC Signature (Step 2 Only)

### Algorithm

```javascript
// 1. Compute SHA-256 hash of PLAINTEXT body (before encryption)
const bodyHash = sha256_hex(plaintext_body);

// 2. Build string-to-sign
const stringToSign = `POST\n/api/v1/token/issue\n${timestamp}\n${nonce}\n${bodyHash}`;

// 3. Compute HMAC-SHA256
const signature = hmac_sha256_hex(client_secret, stringToSign);

// 4. Send in X-Signature header
headers['X-Signature'] = signature;  // hex-encoded lowercase
```

### Key Points

- **HMAC is computed over PLAINTEXT** body (before AES-256-GCM encryption)
- **Signature is hex-encoded lowercase** (64 characters)
- **ONLY Step 2 uses HMAC** - other steps use Bearer token
- **WASM handles all crypto** - JavaScript never sees the client secret

## Architecture

```
Browser
  │
  ├─> Rust WASM Module (all crypto operations)
  │    ├─ ECDH P-256 key exchange
  │    ├─ HKDF-SHA256 session key derivation
  │    ├─ AES-256-GCM encryption/decryption
  │    ├─ HMAC-SHA256 signature (Step 2 only)
  │    └─ Session key storage encryption (WASM_STORAGE_KEY)
  │
  ├─> sessionStorage (only stores ENCRYPTED session key)
  │    ├─ encrypted_session_key (AES-GCM encrypted)
  │    ├─ session_id (plaintext metadata)
  │    └─ kid (plaintext metadata)
  │
  └─> Sidecar API (receives HMAC-authenticated encrypted payloads)
```

## 6-Step Journey

| Step | WASM Operation | Authentication |
|------|---------------|----------------|
| 1 | ECDH key exchange → derive session key | Anonymous (X-ClientId) |
| 2 | **Compute HMAC** → Encrypt token request | **HMAC-SHA256 (X-Signature)** |
| 3 | Decrypt introspection response | Bearer token |
| 4 | New authenticated ECDH session | Bearer token + X-Subject |
| 5 | Encrypt token refresh request | Bearer token |
| 6 | Revoke tokens | Bearer token |

## Comparison with Internal Client

| Feature | External Client | Internal Client |
|---------|----------------|-----------------|
| **Step 2 Auth** | HMAC-SHA256 (X-Signature) | Basic Auth |
| **Step 2 Header** | `X-Signature: {hmac}` | `Authorization: Basic {base64}` |
| **Other Steps** | Same (Bearer token) | Same (Bearer token) |
| **WASM Functions** | + `compute_hmac_signature()` | (not needed) |
| **Dependencies** | + hmac, hex | (not needed) |

## WASM API

### External Client Specific

```javascript
// Compute HMAC-SHA256 signature
const signature = compute_hmac_signature(
  'POST',                    // method
  '/api/v1/token/issue',     // path
  timestamp,                 // Unix ms
  nonce,                     // UUID v4
  plaintextBody,             // BEFORE encryption
  clientSecret               // from config
);
// Returns: hex-encoded lowercase (64 chars)
```

### Common Functions (same as internal)

```javascript
await init();                                          // Initialize WASM
const session = await init_session(...);               // ECDH session
session.encrypt(plaintext, timestamp, nonce);          // Encrypt
session.decrypt(ciphertext, timestamp, nonce);         // Decrypt
generate_nonce();                                      // UUID v4
```

## Build & Development

```bash
# Build WASM
./build.sh

# Or manually
source .env && wasm-pack build --target web --out-dir www/pkg

# Start proxy
node proxy-server.js
```

## Security Considerations

1. **HMAC Signature**: The `client_secret` is embedded in WASM and can be extracted by reverse engineering. This is acceptable for defense-in-depth but should not be the sole security measure.

2. **Signature Timing**: HMAC is computed before encryption to ensure the signature covers the plaintext data.

3. **Session Key Protection**: The session key is encrypted with `WASM_STORAGE_KEY` before browser storage, preventing casual inspection.

4. **Production Recommendations**:
   - Use HTTPS/TLS for all network traffic
   - Implement server-side signature validation
   - Consider WASM code obfuscation
   - Add integrity checks (subresource integrity)

## License

This is a demonstration example for educational purposes.

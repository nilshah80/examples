# Identity Service — Rust WASM Example (Internal Client)

OAuth2 token lifecycle with AES-256-GCM encryption running entirely in **WebAssembly**.

**Client Type:** Internal Client (Basic Auth) — similar to `rust-internal`, `go-internal`, `python-internal`

**Key Security Feature:** A **static encryption key embedded in WASM** encrypts the session key before storing it in `sessionStorage`. JavaScript and browser developer tools can **only see the encrypted session key**, never the plaintext.

## What You'll See in Browser DevTools

**sessionStorage** (Application tab):
```
encrypted_session_key: "rBkVGxIVGhUbFRsVGxU..."  ← AES-256-GCM encrypted
session_id: "k001:uuid..."
kid: "k001"
authenticated: "false"
```

**What JavaScript CANNOT see:**
- ❌ Plaintext 32-byte session key (only exists in WASM memory)

## Prerequisites

- Rust toolchain (rustc/cargo)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) for building WASM
- A local web server (e.g., `python3 -m http.server`)
- Identity Sidecar accessible at `http://localhost:8141`
- The `dev-client` client must exist in the database

## Client Configuration

| Field | Value |
|-------|-------|
| Client ID | `dev-client` |
| Client Secret | `DevSec-LwgT7vXGZk2njwglKWZBYW7q1sdNTElTQ!` |
| Auth Method | Basic Auth (same as rust-internal) |
| Scopes | `orders.read orders.write` |
| Audience | `orders-api` |
| Subject | `test-user` |
| Sidecar URL | `http://localhost:8141` |

> **Note**: The credentials above are **dummy values for testing only**. Configuration is **injected at build time** from [.env](.env) file into the WASM binary. JavaScript never sees the raw config values.

## Quick Start

```bash
cd examples/rust-wasm-internal

# 1. Configure (edit .env file)
cp .env.example .env  # if needed
vim .env              # set SIDECAR_URL, CLIENT_ID, etc.

# 2. Build WASM module (injects .env values)
./build.sh
# OR manually:
source .env && wasm-pack build --target web --out-dir www/pkg

# 3. Start local web server
cd www
python3 -m http.server 8080

# 4. Open browser
open http://localhost:8080
```

### How Configuration Works

**Build-time injection** (Option 3):
- Configuration from `.env` is embedded into WASM binary at build time
- JavaScript fetches config from WASM using `get_sidecar_url()`, `get_client_id()`, etc.
- Config is NOT visible in HTML source code (only in WASM binary)
- Requires rebuild if config changes

Example:
```bash
# .env file
SIDECAR_URL=https://api.example.com
CLIENT_ID=my-client

# Build embeds these values into WASM
./build.sh

# JavaScript loads from WASM (not from HTML)
const config = {
  sidecarUrl: get_sidecar_url(),  // from WASM
  clientId: get_client_id()       // from WASM
};
```

## Architecture

```
Browser
  │
  ├─> Rust WASM Module (all crypto operations)
  │    ├─ ECDH P-256 key exchange
  │    ├─ HKDF-SHA256 session key derivation
  │    ├─ AES-256-GCM encryption/decryption
  │    └─ Session key storage encryption (WASM_STORAGE_KEY)
  │
  ├─> sessionStorage (only stores ENCRYPTED session key)
  │    ├─ session_id (plaintext metadata)
  │    ├─ encrypted_session_key (AES-GCM encrypted with WASM_STORAGE_KEY)
  │    ├─ kid (plaintext metadata)
  │    └─ authenticated (plaintext metadata)
  │
  └─> Sidecar API (receives encrypted payloads)
       └─> Identity API (8140)
```

## Security Model

### Static WASM Encryption Key

The WASM module contains a **hardcoded 32-byte key** (`WASM_STORAGE_KEY`) used exclusively to encrypt/decrypt the session key before browser storage:

```rust
const WASM_STORAGE_KEY: [u8; 32] = [
    0x2a, 0x7b, 0x91, 0x4c, 0x65, 0xe8, 0x3f, 0xa9,
    0x1d, 0x52, 0xb3, 0x7e, 0x94, 0x0f, 0x6c, 0x28,
    0x83, 0xa4, 0x5d, 0x19, 0xf7, 0x2b, 0x68, 0x9a,
    0x3e, 0xd1, 0x4f, 0x86, 0x5c, 0x20, 0x97, 0xb5,
];
```

**Important:**
- This key is embedded in the compiled WASM binary
- It can be extracted by a determined attacker with reverse engineering
- However, it provides **defense in depth** against casual inspection via browser DevTools
- In production, consider additional protections (code obfuscation, integrity checks, server-side validation)

### Storage Choice: sessionStorage vs localStorage

This example uses **sessionStorage** (recommended) because:

| Feature | sessionStorage | localStorage |
|---------|---------------|--------------|
| **Lifetime** | Cleared when tab closes | Persists indefinitely |
| **Scope** | Isolated per tab | Shared across all tabs |
| **Security** | ✅ Better (auto-cleanup) | ❌ Worse (manual cleanup required) |
| **Use Case** | Temporary session data | Long-term user preferences |

**Why sessionStorage is better for session keys:**
1. **Auto-cleanup:** Session keys are automatically cleared when the user closes the tab
2. **Tab isolation:** Each tab has its own session (prevents cross-tab attacks)
3. **Reduced attack surface:** Keys don't persist after browsing session ends

## 6-Step Journey

| Step | WASM Operation | Storage |
|------|---------------|---------|
| 1 | ECDH key exchange → derive session key | **Encrypt session key** with `WASM_STORAGE_KEY` → save to sessionStorage |
| 2 | Encrypt token request with session key | Read encrypted session key → decrypt in WASM → encrypt payload |
| 3 | Decrypt introspection response | Same as above |
| 4 | New authenticated ECDH session | **Replace** encrypted session key in storage |
| 5 | Encrypt token refresh request | Read encrypted session key → decrypt → encrypt payload |
| 6 | Revoke tokens | **Clear** encrypted session key from storage |

## WASM API

### Functions

```javascript
// Initialize WASM module (call once on page load)
await init();

// Create session with ECDH key exchange
const session = await init_session(sidecarUrl, clientId, accessToken?, subject?);

// Session methods
session.encrypt(plaintext, timestamp, nonce);       // Encrypt with session key
session.decrypt(ciphertext, timestamp, nonce);      // Decrypt with session key
session.save_to_storage();                          // Save encrypted to sessionStorage
SessionContext.load_from_storage();                 // Load and decrypt from sessionStorage
SessionContext.clear_storage();                     // Clear all session data

// Utilities
generate_nonce();                                   // UUID v4
generate_timestamp();                               // ISO 8601
```

## File Structure

```
rust-wasm/
├── Cargo.toml                 WASM dependencies (wasm-bindgen, p256, aes-gcm)
├── src/
│   └── lib.rs                 WASM crypto module (ECDH, AES-GCM, storage encryption)
├── www/
│   ├── index.html             Web UI (imports WASM as ES module)
│   └── pkg/                   Generated WASM files (created by wasm-pack)
└── README.md
```

## Development

### Rebuild WASM

```bash
wasm-pack build --target web --out-dir www/pkg
```

### Inspect WASM Binary

```bash
# View exports
wasm-objdump -x www/pkg/rust_wasm_bg.wasm | grep export

# Disassemble (to verify WASM_STORAGE_KEY is embedded)
wasm-objdump -d www/pkg/rust_wasm_bg.wasm | grep -A 10 WASM_STORAGE_KEY
```

## Configuration

Edit `www/index.html` to change client config:

```javascript
const CONFIG = {
  sidecarUrl: 'http://localhost:8141',
  clientId: 'dev-client',
  subject: 'test-user',
};
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `Failed to fetch WASM` | Local server not running | Start `python3 -m http.server` |
| `CORS error` | Wrong sidecar URL | Verify sidecar is at `http://localhost:8141` |
| `Session key decryption failed` | Storage corrupted | Clear sessionStorage via DevTools |
| `No session found` | sessionStorage cleared | Run Step 1 to create new session |

## Security Considerations

1. **WASM Key Extraction:** The `WASM_STORAGE_KEY` can be extracted from the compiled WASM binary. This is acceptable for client-side encryption (defense in depth) but should not be relied upon as the sole security measure.

2. **Session Key Rotation:** Session keys are rotated in Step 4 (authenticated ECDH). The old key is zeroized in memory and replaced with a new encrypted key in storage.

3. **Memory Safety:** Rust's ownership model ensures session keys are properly zeroized when dropped.

4. **Browser DevTools:** Even with encrypted storage, an attacker with DevTools access can still:
   - Intercept network traffic (use HTTPS in production)
   - Hook into WASM function calls (use code obfuscation if needed)
   - Extract WASM binary and reverse engineer the key

5. **Production Recommendations:**
   - Use HTTPS/TLS for all network traffic
   - Implement Content Security Policy (CSP)
   - Consider WASM code obfuscation tools
   - Add integrity checks (e.g., subresource integrity)
   - Implement server-side token validation

## Comparison with Other Examples

| Feature | Rust WASM | Rust Internal | Go Internal | Python Internal |
|---------|-----------|---------------|-------------|-----------------|
| **Crypto Location** | Browser (WASM) | Server-side | Server-side | Server-side |
| **Session Key Visible to JS** | ❌ No (encrypted) | N/A | N/A | N/A |
| **Browser Storage** | ✅ sessionStorage | N/A | N/A | N/A |
| **Network Payload** | Encrypted | Encrypted | Encrypted | Encrypted |
| **Use Case** | Client-side apps | Backend services | Backend services | Backend services |

## License

This is a demonstration example for educational purposes. Use at your own risk in production environments.

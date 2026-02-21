# Identity Service — Rust WASM Angular Example (Internal Client)

OAuth2 token lifecycle with AES-256-GCM encryption running entirely in **WebAssembly** using **Angular**.

**Client Type:** Internal Client (Basic Auth) — similar to `rust-internal`, `go-internal`, `python-internal`

**Key Security Feature:** A **static encryption key embedded in WASM** encrypts the session key before storing it in `sessionStorage`. JavaScript and browser developer tools can **only see the encrypted session key**, never the plaintext.

## Architecture

```
Angular App (Port 4200)
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
  └─> Sidecar API via CORS Proxy (Port 4210)
       └─> Identity API (receives encrypted payloads)
```

## Prerequisites

- **Rust toolchain** (rustc/cargo)
- **wasm-pack** - [Install here](https://rustwasm.github.io/wasm-pack/installer/)
- **Node.js & npm** (v18+)
- **Angular CLI** (optional, but recommended)
- **Identity Sidecar** accessible (production or local)

## Quick Start

```bash
cd examples/rust-wasm-angular-internal

# 1. Install dependencies
npm install

# 2. Build WASM module (embeds .env values)
./build.sh

# 3. Start CORS proxy (in one terminal)
node proxy.js
# ✓ Proxy running on http://localhost:4210

# 4. Start Angular dev server (in another terminal)
npm start
# ✓ Angular running on http://localhost:4200

# 5. Open browser
open http://localhost:4200
```

## Configuration

Configuration is stored in `.env` and **injected at WASM build time**:

```bash
# .env file
CLIENT_ID=dev-client
CLIENT_SECRET=DevSec-LwgT7vXGZk2njwglKWZBYW7q1sdNTElTQ!
SUBJECT=test-user

# WASM Configuration (embedded at build time)
WASM_SIDECAR_URL=http://localhost:4210

# Proxy Configuration (used by proxy.js)
REMOTE_SIDECAR_URL=https://mutualfundbeta.abslmfbeta.com/portal/ipapi/uat/identity-sidecar
```

**Important:** After changing `.env`, you must rebuild the WASM module:

```bash
./build.sh  # Rebuilds WASM with new config
```

## How It Works

### 1. WASM Module Loading
Angular loads the Rust WASM module on initialization:

```typescript
// wasm.service.ts
async loadWasm(): Promise<void> {
  const wasmModule = await import('../assets/wasm/rust_wasm_angular_internal.js');
  await wasmModule.default();
  console.log('✅ WASM module loaded');
}
```

### 2. Session Key Encryption
The WASM module encrypts the session key before storing in browser:

```rust
// Static key embedded in WASM binary
const WASM_STORAGE_KEY: [u8; 32] = [ ... ];

// Encrypt session key before storage
fn encrypt_session_key_for_storage(session_key: &[u8; 32]) -> String {
    let cipher = Aes256Gcm::new_from_slice(&WASM_STORAGE_KEY)?;
    // ... encrypt with AES-256-GCM
}
```

### 3. 6-Step OAuth2 Journey

| Step | Operation | Angular Service | WASM Function |
|------|-----------|-----------------|---------------|
| **1** | Session Init (ECDH) | `identityService.step1()` | `init_session()` |
| **2** | Token Issue | `identityService.step2()` | `session.encrypt()` |
| **3** | Token Introspect | `identityService.step3()` | `session.decrypt()` |
| **4** | Session Refresh (Auth ECDH) | `identityService.step4()` | `init_session(token)` |
| **5** | Token Refresh | `identityService.step5()` | `session.encrypt()` |
| **6** | Token Revocation | `identityService.step6()` | `session.decrypt()` |

## Project Structure

```
rust-wasm-angular-internal/
├── src/
│   ├── app/
│   │   ├── app.component.ts        # Main Angular component
│   │   ├── app.component.html      # UI template
│   │   ├── app.component.css       # Styles
│   │   ├── wasm.service.ts         # WASM module wrapper
│   │   ├── identity.service.ts     # 6-step journey logic
│   │   └── app.config.ts           # Angular configuration
│   ├── assets/
│   │   └── wasm/                   # Generated WASM files (from build.sh)
│   ├── index.html                  # Main HTML file
│   └── main.ts                     # Angular bootstrap
├── wasm-src/
│   └── lib.rs                      # Rust WASM crypto module
├── Cargo.toml                      # Rust dependencies
├── package.json                    # Angular dependencies
├── angular.json                    # Angular CLI config
├── build.sh                        # WASM build script
├── proxy.js                        # CORS proxy server
├── .env                            # Configuration (build-time)
└── README.md
```

## Development

### Rebuild WASM Module

```bash
./build.sh
```

This compiles Rust → WASM and outputs to `src/assets/wasm/`.

### Run Angular Dev Server

```bash
npm start
# or
ng serve
```

### Run Proxy Server

```bash
node proxy.js
```

The proxy is required because browsers block direct requests to production sidecar URLs due to CORS policies.

### Build for Production

```bash
# Build WASM
./build.sh

# Build Angular
npm run build
# Output: dist/rust-wasm-angular-internal/browser/
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

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `Failed to load WASM` | WASM module not built | Run `./build.sh` |
| `CORS error` | Proxy not running | Start `node proxy.js` on port 4210 |
| `Session key decryption failed` | Storage corrupted | Clear sessionStorage via DevTools |
| `No session found` | sessionStorage cleared | Run Step 1 to create new session |
| `Angular serve failed` | Dependencies not installed | Run `npm install` |

## Comparison with Other Examples

| Feature | Rust WASM Angular | Rust WASM (Vanilla) | Rust Internal | Go Internal |
|---------|-------------------|---------------------|---------------|-------------|
| **Framework** | Angular | None (Vanilla JS) | Server-side | Server-side |
| **Crypto Location** | Browser (WASM) | Browser (WASM) | Server-side | Server-side |
| **Session Key Visible to JS** | ❌ No (encrypted) | ❌ No (encrypted) | N/A | N/A |
| **Browser Storage** | ✅ sessionStorage | ✅ sessionStorage | N/A | N/A |
| **UI Components** | Angular Components | Plain HTML | Terminal | Terminal |
| **Type Safety** | TypeScript | JavaScript | Rust | Go |

## What You'll See in Browser DevTools

**sessionStorage** (Application tab):
```
encrypted_session_key: "rBkVGxIVGhUbFRsVGxU..."  ← AES-256-GCM encrypted
session_id: "S-uuid..."
kid: "session:S-uuid..."
authenticated: "false"
```

**What JavaScript CANNOT see:**
- ❌ Plaintext 32-byte session key (only exists in WASM memory)

## License

This is a demonstration example for educational purposes. Use at your own risk in production environments.

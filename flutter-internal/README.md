# Identity Service — Internal Client Example (Flutter)

OAuth2 token lifecycle with AES-256-GCM encryption via the sidecar, authenticated using **HTTP Basic Auth**.

Flutter app with a **step-by-step journey UI** using `pointycastle` for ECDH on native and `cryptography` package for web.

## Prerequisites

- Flutter SDK 3.x+
- Identity Sidecar accessible (configured via `config.dart`)
- The `dev-client` client must exist in the database

## Quick Start

```bash
# macOS desktop
cd examples/flutter-internal
flutter run -d macos

# Chrome (web)
flutter run -d chrome
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

> **Note**: The credentials above are **dummy values for testing only**. Replace them with your actual client ID and secret in `lib/config.dart`.

## Architecture

```
Flutter UI  ──>  Dart services  ──>  Sidecar  ──>  Identity API (8140)
     │                │                 │                       │
     │  Button taps    │  Dart crypto     │  Decrypts GCM         │  Plaintext JSON
     │  Material UI     │  ECDH + HKDF    │  Forwards plaintext    │  Processes request
```

**Native (macOS/iOS/Android)**: Uses `pointycastle` for ECDH P-256, `DartAesGcm` and `DartHkdf` from `cryptography/dart.dart`.
**Web**: Uses `Ecdh.p256()` (Web Crypto API) for ECDH, same `DartAesGcm`/`DartHkdf` for the rest.

## Web UI API Endpoints

This is a Flutter app — there are no HTTP endpoints. The UI directly calls Dart services which communicate with the sidecar.

## 6-Step Journey

| Step | Sidecar Endpoint | Auth | Description |
|------|------------------|------|-------------|
| 1 | `POST /api/v1/session/init` | None | ECDH P-256 key exchange + HKDF-SHA256 key derivation |
| 2 | `POST /api/v1/token/issue` | Basic Auth + GCM | Issue access + refresh tokens |
| 3 | `POST /api/v1/introspect` | Bearer + GCM | Verify token is active, retrieve claims |
| 4 | `POST /api/v1/session/init` | Bearer + X-Subject | Authenticated session refresh (1hr TTL) |
| 5 | `POST /api/v1/token` | Bearer + GCM | Rotate tokens using refresh token |
| 6 | `POST /api/v1/revoke` | Bearer + GCM | Revoke refresh token (entire family) |

## Flutter Crypto Implementation

| Operation | Native (pointycastle) | Web (cryptography) |
|-----------|----------------------|--------------------|
| ECDH keypair | `ECKeyGenerator` + `ECCurve_secp256r1()` | `Ecdh.p256(length: 32)` |
| ECDH shared secret | `ECDHBasicAgreement().calculateAgreement()` | `Ecdh.p256().sharedSecretKey()` |
| HKDF-SHA256 | `DartHkdf(Hmac(DartSha256()))` | `DartHkdf(Hmac(DartSha256()))` |
| AES-256-GCM | `DartAesGcm()` | `DartAesGcm()` |

> **Important**: The `cryptography` package's `DartEcdh.p256()` is a stub on native — it throws `UnimplementedError`. Use `pointycastle` for ECDH on native platforms and `kIsWeb` to branch.

## Dependencies

| Package | Purpose |
|---------|---------|
| `cryptography` | AES-GCM, HKDF, ECDH (web only) |
| `pointycastle` | ECDH P-256 (native only) |
| `http` | HTTP client for sidecar API calls |

## File Structure

```
flutter-internal/
├── pubspec.yaml
├── lib/
│   ├── main.dart                    App entry point
│   ├── config.dart                  Client credentials + sidecar URL
│   ├── models/
│   │   ├── session_context.dart     ECDH session state
│   │   ├── step_result.dart         Step execution result
│   │   └── api_models.dart          Request/response DTOs
│   ├── services/
│   │   ├── crypto_service.dart      ECDH, HKDF, AES-GCM (native/web branching)
│   │   ├── session_service.dart     Session init + refresh
│   │   └── identity_service.dart    Token ops (Basic Auth + GCM)
│   └── screens/
│       └── journey_screen.dart      Step-by-step UI
└── README.md
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `UnimplementedError` | Using `DartEcdh` on native | Ensure `pointycastle` is used for ECDH on native platforms |
| 502 Bad Gateway | Sidecar not running | Start sidecar or verify sidecar URL in `config.dart` |
| 401 Unauthorized | Wrong credentials | Verify `dev-client` exists with correct secret |
| Network error | Sidecar unreachable | Verify sidecar URL and availability |

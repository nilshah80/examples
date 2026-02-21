#!/usr/bin/env bash
set -euo pipefail

if [ ! -f .env ]; then
  echo "Missing .env file in $(pwd)" >&2
  exit 1
fi

# Load .env with CRLF-safe parsing so build-time envs are injected reliably.
while IFS= read -r line || [ -n "$line" ]; do
  line="${line%$'\r'}"
  case "$line" in
    ''|\#*) continue ;;
    *=*) export "$line" ;;
  esac
done < .env

echo "Building Rust WASM module..."
echo "  WASM_SIDECAR_URL: ${WASM_SIDECAR_URL:-}"
echo "  CLIENT_ID: ${CLIENT_ID:-}"
echo "  SUBJECT: ${SUBJECT:-}"

wasm-pack build --target web --out-dir public/wasm

echo "WASM module built successfully."
echo "Output: public/wasm/"

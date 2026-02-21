#!/usr/bin/env bash
set -e

echo "📦 Building Rust WASM Module (Angular Internal Client)..."
echo

# Load environment variables from .env file
if [ -f .env ]; then
  export $(cat .env | grep -v '^#' | xargs)
  echo "✓ Loaded config from .env"
  echo "  WASM_SIDECAR_URL=$WASM_SIDECAR_URL"
  echo "  CLIENT_ID=$CLIENT_ID"
  echo "  SUBJECT=$SUBJECT"
  echo
fi

# Build WASM module with environment variables
echo "🦀 Compiling Rust to WebAssembly..."
wasm-pack build --target web --out-dir src/assets/wasm

echo
echo "✅ WASM module built successfully!"
echo "📂 Output: src/assets/wasm/"
echo
echo "Next steps:"
echo "  npm install        # Install Angular dependencies"
echo "  npm start          # Start Angular dev server (port 4200)"
echo "  node proxy.js      # Start CORS proxy (port 4210)"
echo

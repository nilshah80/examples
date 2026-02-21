#!/bin/bash
set -e

echo "🔧 Loading configuration from .env file..."

# Load .env file if it exists
if [ -f .env ]; then
  set -a
  source .env
  set +a
  echo "✅ Loaded: SIDECAR_URL=${SIDECAR_URL}"
  echo "✅ Loaded: CLIENT_ID=${CLIENT_ID}"
  echo "✅ Loaded: SUBJECT=${SUBJECT}"
else
  echo "⚠️  No .env file found, using default values"
fi

echo ""
echo "🦀 Building Rust WASM module with injected config..."
wasm-pack build --target web --out-dir www/pkg

echo ""
echo "✅ Build complete!"
echo ""
echo "📋 Configuration embedded in WASM:"
echo "   SIDECAR_URL: ${SIDECAR_URL:-http://localhost:8141 (default)}"
echo "   CLIENT_ID: ${CLIENT_ID:-dev-client (default)}"
echo "   SUBJECT: ${SUBJECT:-test-user (default)}"
echo ""
echo "To run the example:"
echo "  1. Start the CORS proxy: node proxy-server.js"
echo "  2. Open http://localhost:8080 in your browser"
echo ""

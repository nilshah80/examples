#!/bin/bash
set -e

echo "🔧 Loading configuration from .env file..."

# Load .env file if it exists
if [ -f .env ]; then
  export $(cat .env | grep -v '^#' | xargs)
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
echo "  cd www"
echo "  python3 -m http.server 8080"
echo "  open http://localhost:8080"
echo ""

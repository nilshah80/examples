const http = require('http');
const httpProxy = require('http-proxy');
const fs = require('fs');
const path = require('path');

// Load configuration from .env file
const envPath = path.join(__dirname, '.env');
let REMOTE_SIDECAR_URL = 'https://mutualfundbeta.abslmfbeta.com/portal/ipapi/uat/identity-sidecar';

if (fs.existsSync(envPath)) {
  const envContent = fs.readFileSync(envPath, 'utf-8');
  const remoteMatch = envContent.match(/REMOTE_SIDECAR_URL=(.+)/);
  if (remoteMatch) {
    REMOTE_SIDECAR_URL = remoteMatch[1].trim();
  }
}

const PORT = 4210;
const proxy = httpProxy.createProxyServer({
  changeOrigin: true,
  secure: false,
});

const server = http.createServer((req, res) => {
  // Add CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-ClientId, X-Idempotency-Key, X-Kid, X-Subject');
  res.setHeader('Access-Control-Expose-Headers', 'X-Kid, X-Idempotency-Key, Content-Type');

  // Handle preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  // Proxy API requests to remote sidecar
  proxy.web(req, res, { target: REMOTE_SIDECAR_URL }, (err) => {
    console.error('❌ Proxy error:', err.message);
    res.writeHead(502);
    res.end('Bad Gateway');
  });
});

server.listen(PORT, () => {
  console.log('🚀 CORS Proxy Server Running');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`📍 Local:    http://localhost:${PORT}`);
  console.log(`🔗 Proxying: ${REMOTE_SIDECAR_URL}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('\n💡 Angular dev server should run on port 4200');
  console.log('   Configure Angular app to use http://localhost:4210 for API calls\n');
});

#!/usr/bin/env node

const http = require('http');
const https = require('https');
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

const PORT = 4220;
const SIDECAR_URL = REMOTE_SIDECAR_URL;
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers':
    'Content-Type, Authorization, X-ClientId, X-Idempotency-Key, X-Kid, X-Subject, X-Signature',
  'Access-Control-Expose-Headers': 'X-Kid, X-Idempotency-Key, Content-Type',
};

// Serve static files from www/
const serveStatic = (req, res) => {
  let filePath = path.join(__dirname, 'www', req.url === '/' ? 'index.html' : req.url);

  const ext = path.extname(filePath);
  const contentTypes = {
    '.html': 'text/html',
    '.js': 'application/javascript',
    '.wasm': 'application/wasm',
    '.css': 'text/css',
  };

  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404);
      res.end('Not found');
      return;
    }
    res.writeHead(200, { 'Content-Type': contentTypes[ext] || 'application/octet-stream' });
    res.end(content);
  });
};

// Proxy API requests to sidecar
const proxyRequest = (req, res) => {
  const url = `${SIDECAR_URL}${req.url}`;

  console.log(`[PROXY] ${req.method} ${url}`);

  const options = {
    method: req.method,
    headers: {
      ...req.headers,
      'host': new URL(SIDECAR_URL).host,
    },
  };

  delete options.headers['origin'];
  delete options.headers['referer'];

  const proxyReq = https.request(url, options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, {
      ...proxyRes.headers,
      ...CORS_HEADERS,
    });
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (err) => {
    console.error('[PROXY ERROR]', err.message);
    res.writeHead(502);
    res.end('Bad Gateway');
  });

  req.pipe(proxyReq);
};

const server = http.createServer((req, res) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(200, CORS_HEADERS);
    res.end();
    return;
  }

  // Proxy sidecar API calls
  if (req.url.startsWith('/api/')) {
    proxyRequest(req, res);
  } else {
    serveStatic(req, res);
  }
});

server.listen(PORT, () => {
  console.log(`
🚀 WASM Proxy Server Running
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📍 Local:    http://localhost:${PORT}
🔗 Proxying: ${SIDECAR_URL}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  `);
});

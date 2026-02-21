import init, {
  init_session,
  SessionContext,
  generate_nonce,
  get_sidecar_url,
  get_client_id,
  get_client_secret,
  get_subject
} from './pkg/rust_wasm.js';

// Initialize WASM and load configuration from build-time env
await init();

// Configuration loaded from WASM (injected at build time)
const CONFIG = {
  sidecarUrl: get_sidecar_url(),
  clientId: get_client_id(),
  clientSecret: get_client_secret(),
  subject: get_subject(),
};

console.log('🔧 WASM Config loaded:', {
  sidecarUrl: CONFIG.sidecarUrl,
  clientId: CONFIG.clientId,
  subject: CONFIG.subject
});

const STEPS = [
  {
    n: 1,
    title: 'Session Init (Anonymous ECDH)',
    desc: 'Generate ECDH P-256 keypair in WASM, exchange with sidecar, derive AES-256-GCM session key. Session key is encrypted and saved to sessionStorage.',
    endpoint: 'POST /api/v1/session/init',
    session: true
  },
  {
    n: 2,
    title: 'Token Issue (Basic Auth + GCM)',
    desc: 'WASM encrypts request body with AES-256-GCM. Issues access + refresh tokens.',
    endpoint: 'POST /api/v1/token/issue'
  },
  {
    n: 3,
    title: 'Token Introspection (Bearer + GCM)',
    desc: 'Verify the issued token is active. WASM handles all encryption/decryption.',
    endpoint: 'POST /api/v1/introspect'
  },
  {
    n: 4,
    title: 'Session Refresh (Authenticated)',
    desc: 'Create new authenticated session. Old session key is replaced with new encrypted key.',
    endpoint: 'POST /api/v1/session/init',
    session: true
  },
  {
    n: 5,
    title: 'Token Refresh (Bearer + GCM)',
    desc: 'Rotate tokens using refresh token. Uses authenticated session.',
    endpoint: 'POST /api/v1/token'
  },
  {
    n: 6,
    title: 'Token Revocation (Bearer + GCM)',
    desc: 'Revoke refresh token (entire family). Clears encrypted session from storage.',
    endpoint: 'POST /api/v1/revoke'
  },
];

let state = {
  currentStep: 1,
  loading: {},
  results: {},
  session: null,
  accessToken: null,
  refreshToken: null,
};

async function runStep(n) {
  state.loading[n] = true;
  render();

  try {
    let result;
    switch (n) {
      case 1:
        result = await step1();
        break;
      case 2:
        result = await step2();
        break;
      case 3:
        result = await step3();
        break;
      case 4:
        result = await step4();
        break;
      case 5:
        result = await step5();
        break;
      case 6:
        result = await step6();
        break;
    }

    state.results[n] = result;
    if (result.success) {
      state.currentStep = n + 1;
    }
  } catch (error) {
    state.results[n] = {
      success: false,
      error: error.message || String(error)
    };
  }

  state.loading[n] = false;
  render();
}

async function step1() {
  const start = Date.now();
  state.session = await init_session(
    CONFIG.sidecarUrl,
    CONFIG.clientId,
    null,
    null
  );

  // Save encrypted session to storage
  state.session.save_to_storage();

  return {
    success: true,
    durationMs: Date.now() - start,
    sessionId: state.session.session_id,
    kid: state.session.kid,
    authenticated: state.session.authenticated,
    expiresInSec: state.session.expires_in_sec,
    storageNote: '✅ Session key encrypted and saved to sessionStorage'
  };
}

async function step2() {
  if (!state.session) throw new Error('Run step 1 first');

  const start = Date.now();
  const timestamp = Date.now().toString();
  const nonce = generate_nonce();

  const requestBody = {
    audience: 'orders-api',
    scope: 'orders.read orders.write',
    subject: CONFIG.subject,
    include_refresh_token: true,
    single_session: true,
    custom_claims: { roles: 'admin', tenant: 'test-corp' }
  };

  const plaintext = JSON.stringify(requestBody);
  const encrypted = state.session.encrypt(plaintext, timestamp, nonce);

  const requestHeaders = {
    'Content-Type': 'application/json',
    'X-ClientId': CONFIG.clientId,
    'X-Idempotency-Key': `${timestamp}.${nonce}`,
    'X-Kid': state.session.kid,
    'Authorization': 'Basic ' + btoa(`${CONFIG.clientId}:${CONFIG.clientSecret}`)
  };

  const response = await fetch(`${CONFIG.sidecarUrl}/api/v1/token/issue`, {
    method: 'POST',
    headers: requestHeaders,
    body: JSON.stringify({ payload: encrypted })
  });

  if (!response.ok) throw new Error(`HTTP ${response.status}`);

  const responseHeaders = {
    'x-kid': response.headers.get('x-kid'),
    'x-idempotency-key': response.headers.get('x-idempotency-key'),
    'content-type': response.headers.get('content-type')
  };

  const respIdempKey = response.headers.get('X-Idempotency-Key');
  const [respTimestamp, respNonce] = respIdempKey.split('.');
  const data = await response.json();
  const decrypted = state.session.decrypt(data.payload, respTimestamp, respNonce);
  const tokens = JSON.parse(decrypted);

  state.accessToken = tokens.access_token;
  state.refreshToken = tokens.refresh_token;

  return {
    success: true,
    durationMs: Date.now() - start,
    requestHeaders: requestHeaders,
    requestBodyPlaintext: plaintext,
    requestBodyEncrypted: encrypted,
    responseHeaders: responseHeaders,
    responseBodyEncrypted: data.payload,
    responseBodyDecrypted: decrypted
  };
}

async function step3() {
  if (!state.session || !state.accessToken) throw new Error('Run steps 1-2 first');

  const start = Date.now();
  const timestamp = Date.now().toString();
  const nonce = generate_nonce();

  const requestBody = { token: state.accessToken };
  const plaintext = JSON.stringify(requestBody);
  const encrypted = state.session.encrypt(plaintext, timestamp, nonce);

  const requestHeaders = {
    'Content-Type': 'application/json',
    'X-ClientId': CONFIG.clientId,
    'X-Idempotency-Key': `${timestamp}.${nonce}`,
    'X-Kid': state.session.kid,
    'Authorization': `Bearer ${state.accessToken}`
  };

  const response = await fetch(`${CONFIG.sidecarUrl}/api/v1/introspect`, {
    method: 'POST',
    headers: requestHeaders,
    body: JSON.stringify({ payload: encrypted })
  });

  if (!response.ok) throw new Error(`HTTP ${response.status}`);

  const responseHeaders = {
    'x-kid': response.headers.get('x-kid'),
    'x-idempotency-key': response.headers.get('x-idempotency-key'),
    'content-type': response.headers.get('content-type')
  };

  const respIdempKey = response.headers.get('X-Idempotency-Key');
  const [respTimestamp, respNonce] = respIdempKey.split('.');
  const data = await response.json();
  const decrypted = state.session.decrypt(data.payload, respTimestamp, respNonce);

  return {
    success: true,
    durationMs: Date.now() - start,
    requestHeaders: requestHeaders,
    requestBodyPlaintext: plaintext,
    requestBodyEncrypted: encrypted,
    responseHeaders: responseHeaders,
    responseBodyEncrypted: data.payload,
    responseBodyDecrypted: decrypted
  };
}

async function step4() {
  if (!state.session || !state.accessToken) throw new Error('Run steps 1-3 first');

  const start = Date.now();

  // Create new authenticated session (old session key is zeroized in WASM)
  state.session = await init_session(
    CONFIG.sidecarUrl,
    CONFIG.clientId,
    state.accessToken,
    CONFIG.subject
  );

  // Save new encrypted session to storage
  state.session.save_to_storage();

  return {
    success: true,
    durationMs: Date.now() - start,
    sessionId: state.session.session_id,
    kid: state.session.kid,
    authenticated: state.session.authenticated,
    expiresInSec: state.session.expires_in_sec,
    storageNote: '✅ Authenticated session established (old session key zeroized)'
  };
}

async function step5() {
  if (!state.session || !state.refreshToken) throw new Error('Run steps 1-4 first');

  const start = Date.now();
  const timestamp = Date.now().toString();
  const nonce = generate_nonce();

  const requestBody = {
    grant_type: 'refresh_token',
    refresh_token: state.refreshToken
  };
  const plaintext = JSON.stringify(requestBody);
  const encrypted = state.session.encrypt(plaintext, timestamp, nonce);

  const requestHeaders = {
    'Content-Type': 'application/json',
    'X-ClientId': CONFIG.clientId,
    'X-Idempotency-Key': `${timestamp}.${nonce}`,
    'X-Kid': state.session.kid,
    'Authorization': `Bearer ${state.accessToken}`
  };

  const response = await fetch(`${CONFIG.sidecarUrl}/api/v1/token`, {
    method: 'POST',
    headers: requestHeaders,
    body: JSON.stringify({ payload: encrypted })
  });

  if (!response.ok) throw new Error(`HTTP ${response.status}`);

  const responseHeaders = {
    'x-kid': response.headers.get('x-kid'),
    'x-idempotency-key': response.headers.get('x-idempotency-key'),
    'content-type': response.headers.get('content-type')
  };

  const respIdempKey = response.headers.get('X-Idempotency-Key');
  const [respTimestamp, respNonce] = respIdempKey.split('.');
  const data = await response.json();
  const decrypted = state.session.decrypt(data.payload, respTimestamp, respNonce);
  const tokens = JSON.parse(decrypted);

  state.accessToken = tokens.access_token;
  state.refreshToken = tokens.refresh_token;

  return {
    success: true,
    durationMs: Date.now() - start,
    requestHeaders: requestHeaders,
    requestBodyPlaintext: plaintext,
    requestBodyEncrypted: encrypted,
    responseHeaders: responseHeaders,
    responseBodyEncrypted: data.payload,
    responseBodyDecrypted: decrypted
  };
}

async function step6() {
  if (!state.session || !state.refreshToken) throw new Error('Run steps 1-5 first');

  const start = Date.now();
  const timestamp = Date.now().toString();
  const nonce = generate_nonce();

  const requestBody = {
    token: state.refreshToken,
    token_type_hint: 'refresh_token'
  };
  const plaintext = JSON.stringify(requestBody);
  const encrypted = state.session.encrypt(plaintext, timestamp, nonce);

  const requestHeaders = {
    'Content-Type': 'application/json',
    'X-ClientId': CONFIG.clientId,
    'X-Idempotency-Key': `${timestamp}.${nonce}`,
    'X-Kid': state.session.kid,
    'Authorization': `Bearer ${state.accessToken}`
  };

  const response = await fetch(`${CONFIG.sidecarUrl}/api/v1/revoke`, {
    method: 'POST',
    headers: requestHeaders,
    body: JSON.stringify({ payload: encrypted })
  });

  if (!response.ok) throw new Error(`HTTP ${response.status}`);

  const responseHeaders = {
    'x-kid': response.headers.get('x-kid'),
    'x-idempotency-key': response.headers.get('x-idempotency-key'),
    'content-type': response.headers.get('content-type')
  };

  const respIdempKey = response.headers.get('X-Idempotency-Key');
  const [respTimestamp, respNonce] = respIdempKey.split('.');
  const data = await response.json();
  const decrypted = state.session.decrypt(data.payload, respTimestamp, respNonce);

  // Clear encrypted session from storage
  SessionContext.clear_storage();

  return {
    success: true,
    durationMs: Date.now() - start,
    requestHeaders: requestHeaders,
    requestBodyPlaintext: plaintext,
    requestBodyEncrypted: encrypted,
    responseHeaders: responseHeaders,
    responseBodyEncrypted: data.payload,
    responseBodyDecrypted: decrypted,
    storageNote: '✅ Token revoked, session cleared from sessionStorage'
  };
}

async function resetAll() {
  SessionContext.clear_storage();
  state = {
    currentStep: 1,
    loading: {},
    results: {},
    session: null,
    accessToken: null,
    refreshToken: null,
  };
  render();
}

function render() {
  const app = document.getElementById('app');
  let html = '<div class="steps">';

  STEPS.forEach(step => {
    const result = state.results[step.n];
    const canRun = step.n === state.currentStep;
    const isLoading = state.loading[step.n];

    html += `
      <div class="step">
        <div class="step-header">
          <div class="step-title">Step ${step.n}: ${step.title}</div>
          <div class="step-actions">
            <button
              onclick="runStep(${step.n})"
              ${canRun && !isLoading ? '' : 'disabled'}
            >
              ${isLoading ? 'Running...' : step.endpoint}
              ${isLoading ? '<span class="spinner"></span>' : ''}
            </button>
          </div>
        </div>
        <div class="step-desc">${step.desc}</div>
        ${result ? renderResult(result) : ''}
      </div>
    `;
  });

  html += `
    <div style="text-align: center; margin-top: 2rem;">
      <button class="reset" onclick="resetAll()">🔄 Reset All</button>
    </div>
  `;
  html += '</div>';

  app.innerHTML = html;
}

function renderResult(r) {
  if (!r) return '';
  const status = r.success ? 'success' : 'error';
  const statusText = r.success ? 'Success' : 'Failed';
  const statusClass = r.success ? 'success-text' : 'error-text';

  let html = `<div class="result ${status}">`;
  html += `<div class="result-header">`;
  html += `<span class="${statusClass}">${statusText}</span>`;
  html += `<span>${r.durationMs || 0}ms</span>`;
  html += `</div>`;

  if (r.error) {
    html += `<div style="color: #ef4444; margin-top: 0.5rem;">${escapeHtml(r.error)}</div>`;
  }

  if (r.sessionId) {
    html += `<div class="kv"><span>Session ID</span><code>${escapeHtml(r.sessionId)}</code></div>`;
    html += `<div class="kv"><span>Kid</span><code>${escapeHtml(r.kid)}</code></div>`;
    html += `<div class="kv"><span>Authenticated</span><code>${r.authenticated}</code></div>`;
    html += `<div class="kv"><span>TTL</span><code>${r.expiresInSec}s</code></div>`;
  }

  if (r.storageNote) {
    html += `<div style="margin-top: 0.5rem; color: #10b981;">${r.storageNote}</div>`;
  }

  if (r.requestHeaders) {
    html += `<details><summary>Request Headers</summary><pre>${escapeHtml(formatJson(JSON.stringify(r.requestHeaders)))}</pre></details>`;
  }
  if (r.requestBodyPlaintext) {
    html += `<details><summary>Request Body (plaintext)</summary><pre>${escapeHtml(formatJson(r.requestBodyPlaintext))}</pre></details>`;
  }
  if (r.requestBodyEncrypted) {
    html += `<details><summary>Request Body (encrypted)</summary><pre>${escapeHtml(truncate(r.requestBodyEncrypted, 500))}</pre></details>`;
  }
  if (r.responseHeaders) {
    html += `<details><summary>Response Headers</summary><pre>${escapeHtml(formatJson(JSON.stringify(r.responseHeaders)))}</pre></details>`;
  }
  if (r.responseBodyEncrypted) {
    html += `<details><summary>Response Body (encrypted)</summary><pre>${escapeHtml(truncate(r.responseBodyEncrypted, 500))}</pre></details>`;
  }
  if (r.responseBodyDecrypted) {
    html += `<details open><summary>Response Body (decrypted)</summary><pre>${escapeHtml(formatJson(r.responseBodyDecrypted))}</pre></details>`;
  }

  html += '</div>';
  return html;
}

function formatJson(str) {
  try {
    return JSON.stringify(JSON.parse(str), null, 2);
  } catch (e) {
    return str;
  }
}

function truncate(str, maxLen) {
  if (str.length <= maxLen) return str;
  return str.substring(0, maxLen) + `...\n\n[Truncated - Total length: ${str.length} chars]`;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Expose functions to window
window.runStep = runStep;
window.resetAll = resetAll;

// Render (WASM already initialized at top)
render();

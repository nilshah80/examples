import init, {
  init_session,
  SessionContext,
  get_sidecar_url,
  get_client_id,
  get_subject
} from './pkg/rust_wasm_external.js';

// Initialize WASM and load configuration from build-time env
await init();

// Note: clientSecret is NOT exposed to JS — it stays inside WASM
const CONFIG = {
  sidecarUrl: get_sidecar_url(),
  clientId: get_client_id(),
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
    title: 'Token Issue (HMAC + GCM)',
    desc: 'WASM computes HMAC-SHA256 signature, encrypts request, makes HTTP call, decrypts response, and stores tokens encrypted — all inside WASM.',
    endpoint: 'POST /api/v1/token/issue'
  },
  {
    n: 3,
    title: 'Token Introspection (Bearer + GCM)',
    desc: 'WASM loads access token from encrypted storage, builds request, and handles full encrypt/HTTP/decrypt cycle internally.',
    endpoint: 'POST /api/v1/introspect'
  },
  {
    n: 4,
    title: 'Session Refresh (Authenticated)',
    desc: 'WASM loads access token from encrypted storage, performs authenticated ECDH, migrates tokens to new session key.',
    endpoint: 'POST /api/v1/session/init',
    session: true
  },
  {
    n: 5,
    title: 'Token Refresh (Bearer + GCM)',
    desc: 'WASM loads tokens from encrypted storage, rotates them via sidecar, re-encrypts new tokens in storage.',
    endpoint: 'POST /api/v1/token'
  },
  {
    n: 6,
    title: 'Token Revocation (Bearer + GCM)',
    desc: 'WASM loads tokens, revokes via sidecar, clears all encrypted data from sessionStorage.',
    endpoint: 'POST /api/v1/revoke'
  },
];

let state = {
  currentStep: 1,
  loading: {},
  results: {},
  session: null,
};

async function runStep(n) {
  state.loading[n] = true;
  render();

  try {
    let result;
    switch (n) {
      case 1: result = await step1(); break;
      case 2: result = await step2(); break;
      case 3: result = await step3(); break;
      case 4: result = await step4(); break;
      case 5: result = await step5(); break;
      case 6: result = await step6(); break;
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
  state.session = await init_session(CONFIG.sidecarUrl, CONFIG.clientId, null, null);
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
  const requestBody = {
    audience: 'orders-api',
    custom_claims: { partner_id: 'PARTNER-001', region: 'us-east-1' },
    include_refresh_token: true,
    scope: 'orders.read',
    single_session: true,
    subject: CONFIG.subject
  };

  const resultJson = await state.session.issue_token(JSON.stringify(requestBody));
  const result = JSON.parse(resultJson);

  return {
    success: true,
    durationMs: Date.now() - start,
    requestHeaders: result.requestHeaders,
    requestBodyPlaintext: result.requestBodyPlaintext,
    requestBodyEncrypted: result.requestBodyEncrypted,
    responseHeaders: result.responseHeaders,
    responseBodyEncrypted: result.responseBodyEncrypted,
    responseBodyDecrypted: result.responseBodyDecrypted,
    storageNote: '✅ Tokens encrypted and stored in sessionStorage (never exposed to JS)'
  };
}

async function step3() {
  if (!state.session) throw new Error('Run steps 1-2 first');
  const start = Date.now();
  const resultJson = await state.session.introspect_token();
  const result = JSON.parse(resultJson);

  return {
    success: true,
    durationMs: Date.now() - start,
    requestHeaders: result.requestHeaders,
    requestBodyPlaintext: result.requestBodyPlaintext,
    requestBodyEncrypted: result.requestBodyEncrypted,
    responseHeaders: result.responseHeaders,
    responseBodyEncrypted: result.responseBodyEncrypted,
    responseBodyDecrypted: result.responseBodyDecrypted
  };
}

async function step4() {
  if (!state.session) throw new Error('Run steps 1-3 first');
  const start = Date.now();
  state.session = await state.session.refresh_session();

  return {
    success: true,
    durationMs: Date.now() - start,
    sessionId: state.session.session_id,
    kid: state.session.kid,
    authenticated: state.session.authenticated,
    expiresInSec: state.session.expires_in_sec,
    storageNote: '✅ Authenticated session established, tokens migrated to new key'
  };
}

async function step5() {
  if (!state.session) throw new Error('Run steps 1-4 first');
  const start = Date.now();
  const resultJson = await state.session.refresh_tokens();
  const result = JSON.parse(resultJson);

  return {
    success: true,
    durationMs: Date.now() - start,
    requestHeaders: result.requestHeaders,
    requestBodyPlaintext: result.requestBodyPlaintext,
    requestBodyEncrypted: result.requestBodyEncrypted,
    responseHeaders: result.responseHeaders,
    responseBodyEncrypted: result.responseBodyEncrypted,
    responseBodyDecrypted: result.responseBodyDecrypted,
    storageNote: '✅ Tokens rotated and re-encrypted in sessionStorage'
  };
}

async function step6() {
  if (!state.session) throw new Error('Run steps 1-5 first');
  const start = Date.now();
  const resultJson = await state.session.revoke_tokens();
  const result = JSON.parse(resultJson);
  state.session = null;

  return {
    success: true,
    durationMs: Date.now() - start,
    requestHeaders: result.requestHeaders,
    requestBodyPlaintext: result.requestBodyPlaintext,
    requestBodyEncrypted: result.requestBodyEncrypted,
    responseHeaders: result.responseHeaders,
    responseBodyEncrypted: result.responseBodyEncrypted,
    responseBodyDecrypted: result.responseBodyDecrypted,
    storageNote: '✅ Token revoked, session and tokens cleared from sessionStorage'
  };
}

async function resetAll() {
  SessionContext.clear_storage();
  state = { currentStep: 1, loading: {}, results: {}, session: null };
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
  try { return JSON.stringify(JSON.parse(str), null, 2); } catch (e) { return str; }
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

window.runStep = runStep;
window.resetAll = resetAll;
render();

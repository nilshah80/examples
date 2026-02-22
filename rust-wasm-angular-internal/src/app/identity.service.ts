import { Injectable } from '@angular/core';
import { WasmService } from './wasm.service';

export interface StepResult {
  step: number;
  name: string;
  success: boolean;
  durationMs: number;
  sessionId?: string;
  kid?: string;
  authenticated?: boolean;
  expiresInSec?: number;
  requestHeaders?: any;
  requestBodyPlaintext?: string;
  requestBodyEncrypted?: string;
  responseHeaders?: any;
  responseBodyEncrypted?: string;
  responseBodyDecrypted?: string;
  error?: string;
  storageNote?: string;
}

export interface AppState {
  session: any | null;
}

@Injectable({
  providedIn: 'root'
})
export class IdentityService {
  private state: AppState = {
    session: null
  };

  private config = {
    sidecarUrl: '',
    clientId: '',
    subject: ''
  };

  constructor(
    private wasmService: WasmService
  ) {}

  async initialize(): Promise<void> {
    await this.wasmService.loadWasm();
    this.config.sidecarUrl = this.wasmService.getSidecarUrl();
    this.config.clientId = this.wasmService.getClientId();
    this.config.subject = this.wasmService.getSubject();

    console.log('🔧 WASM Config loaded:', {
      sidecarUrl: this.config.sidecarUrl,
      clientId: this.config.clientId,
      subject: this.config.subject
    });
  }

  getConfig() {
    return this.config;
  }

  getState() {
    return this.state;
  }

  async step1(): Promise<StepResult> {
    const start = Date.now();

    try {
      this.state.session = await this.wasmService.initSession(
        this.config.sidecarUrl,
        this.config.clientId,
        undefined,
        this.config.subject
      );

      this.state.session.save_to_storage();

      return {
        step: 1,
        name: 'Session Init (Anonymous ECDH)',
        success: true,
        durationMs: Date.now() - start,
        sessionId: this.state.session.session_id,
        kid: this.state.session.kid,
        authenticated: this.state.session.authenticated,
        expiresInSec: this.state.session.expires_in_sec,
        storageNote: '✅ Session key encrypted and saved to sessionStorage'
      };
    } catch (error: any) {
      return {
        step: 1,
        name: 'Session Init (Anonymous ECDH)',
        success: false,
        durationMs: Date.now() - start,
        error: error.message || String(error)
      };
    }
  }

  async step2(): Promise<StepResult> {
    if (!this.state.session) {
      throw new Error('Run step 1 first');
    }

    const start = Date.now();

    try {
      const requestBody = {
        audience: 'orders-api',
        scope: 'orders.read orders.write',
        subject: this.config.subject,
        include_refresh_token: true,
        single_session: true,
        custom_claims: { roles: 'admin', tenant: 'test-corp' }
      };

      // WASM handles: timestamp/nonce, encryption, HTTP call, decryption, token storage
      const resultJson = await this.state.session.issue_token(JSON.stringify(requestBody));
      const result = JSON.parse(resultJson);

      return {
        step: 2,
        name: 'Token Issue (Basic Auth + GCM)',
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
    } catch (error: any) {
      return {
        step: 2,
        name: 'Token Issue (Basic Auth + GCM)',
        success: false,
        durationMs: Date.now() - start,
        error: error.message || String(error)
      };
    }
  }

  async step3(): Promise<StepResult> {
    if (!this.state.session) {
      throw new Error('Run steps 1-2 first');
    }

    const start = Date.now();

    try {
      // WASM loads access token from encrypted storage internally
      const resultJson = await this.state.session.introspect_token();
      const result = JSON.parse(resultJson);

      return {
        step: 3,
        name: 'Token Introspection (Bearer + GCM)',
        success: true,
        durationMs: Date.now() - start,
        requestHeaders: result.requestHeaders,
        requestBodyPlaintext: result.requestBodyPlaintext,
        requestBodyEncrypted: result.requestBodyEncrypted,
        responseHeaders: result.responseHeaders,
        responseBodyEncrypted: result.responseBodyEncrypted,
        responseBodyDecrypted: result.responseBodyDecrypted
      };
    } catch (error: any) {
      return {
        step: 3,
        name: 'Token Introspection (Bearer + GCM)',
        success: false,
        durationMs: Date.now() - start,
        error: error.message || String(error)
      };
    }
  }

  async step4(): Promise<StepResult> {
    if (!this.state.session) {
      throw new Error('Run steps 1-3 first');
    }

    const start = Date.now();

    try {
      // WASM loads access token, does authenticated ECDH, migrates tokens
      this.state.session = await this.state.session.refresh_session();

      return {
        step: 4,
        name: 'Session Refresh (Authenticated ECDH)',
        success: true,
        durationMs: Date.now() - start,
        sessionId: this.state.session.session_id,
        kid: this.state.session.kid,
        authenticated: this.state.session.authenticated,
        expiresInSec: this.state.session.expires_in_sec,
        storageNote: '✅ Authenticated session established, tokens migrated to new key'
      };
    } catch (error: any) {
      return {
        step: 4,
        name: 'Session Refresh (Authenticated ECDH)',
        success: false,
        durationMs: Date.now() - start,
        error: error.message || String(error)
      };
    }
  }

  async step5(): Promise<StepResult> {
    if (!this.state.session) {
      throw new Error('Run steps 1-4 first');
    }

    const start = Date.now();

    try {
      // WASM loads both tokens from encrypted storage internally
      const resultJson = await this.state.session.refresh_tokens();
      const result = JSON.parse(resultJson);

      return {
        step: 5,
        name: 'Token Refresh (Bearer + GCM)',
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
    } catch (error: any) {
      return {
        step: 5,
        name: 'Token Refresh (Bearer + GCM)',
        success: false,
        durationMs: Date.now() - start,
        error: error.message || String(error)
      };
    }
  }

  async step6(): Promise<StepResult> {
    if (!this.state.session) {
      throw new Error('Run steps 1-5 first');
    }

    const start = Date.now();

    try {
      // WASM loads tokens, revokes, and clears all storage
      const resultJson = await this.state.session.revoke_tokens();
      const result = JSON.parse(resultJson);

      this.state.session = null;

      return {
        step: 6,
        name: 'Token Revocation (Bearer + GCM)',
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
    } catch (error: any) {
      return {
        step: 6,
        name: 'Token Revocation (Bearer + GCM)',
        success: false,
        durationMs: Date.now() - start,
        error: error.message || String(error)
      };
    }
  }

  reset(): void {
    this.wasmService.clearSessionStorage();
    this.state.session = null;
  }
}

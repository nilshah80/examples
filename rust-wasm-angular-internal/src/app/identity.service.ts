import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
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
  accessToken: string;
  refreshToken: string;
}

@Injectable({
  providedIn: 'root'
})
export class IdentityService {
  private state: AppState = {
    session: null,
    accessToken: '',
    refreshToken: ''
  };

  private config = {
    sidecarUrl: '',
    clientId: '',
    clientSecret: '',
    subject: ''
  };

  constructor(
    private http: HttpClient,
    private wasmService: WasmService
  ) {}

  async initialize(): Promise<void> {
    await this.wasmService.loadWasm();
    this.config.sidecarUrl = this.wasmService.getSidecarUrl();
    this.config.clientId = this.wasmService.getClientId();
    this.config.clientSecret = this.wasmService.getClientSecret();
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
    const timestamp = Date.now().toString();
    const nonce = this.wasmService.generateNonce();

    const requestBody = {
      audience: 'orders-api',
      scope: 'orders.read orders.write',
      subject: this.config.subject,
      include_refresh_token: true,
      single_session: true,
      custom_claims: { roles: 'admin', tenant: 'test-corp' }
    };

    const plaintext = JSON.stringify(requestBody);
    const encrypted = this.state.session.encrypt(plaintext, timestamp, nonce);

    const requestHeaders = {
      'Content-Type': 'application/json',
      'X-ClientId': this.config.clientId,
      'X-Idempotency-Key': `${timestamp}.${nonce}`,
      'X-Kid': this.state.session.kid,
      'Authorization': 'Basic ' + btoa(`${this.config.clientId}:${this.config.clientSecret}`)
    };

    try {
      const response = await firstValueFrom(
        this.http.post<any>(
          `${this.config.sidecarUrl}/api/v1/token/issue`,
          { payload: encrypted },
          { headers: requestHeaders, observe: 'response' }
        )
      );

      const responseHeaders = {
        'x-kid': response.headers.get('x-kid'),
        'x-idempotency-key': response.headers.get('x-idempotency-key'),
        'content-type': response.headers.get('content-type')
      };

      const respIdempKey = response.headers.get('X-Idempotency-Key') || '';
      const [respTimestamp, respNonce] = respIdempKey.split('.');
      const decrypted = this.state.session.decrypt(response.body.payload, respTimestamp, respNonce);
      const tokens = JSON.parse(decrypted);

      this.state.accessToken = tokens.access_token;
      this.state.refreshToken = tokens.refresh_token;

      return {
        step: 2,
        name: 'Token Issue (Basic Auth + GCM)',
        success: true,
        durationMs: Date.now() - start,
        requestHeaders,
        requestBodyPlaintext: plaintext,
        requestBodyEncrypted: encrypted,
        responseHeaders,
        responseBodyEncrypted: response.body.payload,
        responseBodyDecrypted: decrypted
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
    if (!this.state.session || !this.state.accessToken) {
      throw new Error('Run steps 1-2 first');
    }

    const start = Date.now();
    const timestamp = Date.now().toString();
    const nonce = this.wasmService.generateNonce();

    const requestBody = { token: this.state.accessToken };
    const plaintext = JSON.stringify(requestBody);
    const encrypted = this.state.session.encrypt(plaintext, timestamp, nonce);

    const requestHeaders = {
      'Content-Type': 'application/json',
      'X-ClientId': this.config.clientId,
      'X-Idempotency-Key': `${timestamp}.${nonce}`,
      'X-Kid': this.state.session.kid,
      'Authorization': `Bearer ${this.state.accessToken}`
    };

    try {
      const response = await firstValueFrom(
        this.http.post<any>(
          `${this.config.sidecarUrl}/api/v1/introspect`,
          { payload: encrypted },
          { headers: requestHeaders, observe: 'response' }
        )
      );

      const responseHeaders = {
        'x-kid': response.headers.get('x-kid'),
        'x-idempotency-key': response.headers.get('x-idempotency-key'),
        'content-type': response.headers.get('content-type')
      };

      const respIdempKey = response.headers.get('X-Idempotency-Key') || '';
      const [respTimestamp, respNonce] = respIdempKey.split('.');
      const decrypted = this.state.session.decrypt(response.body.payload, respTimestamp, respNonce);

      return {
        step: 3,
        name: 'Token Introspection (Bearer + GCM)',
        success: true,
        durationMs: Date.now() - start,
        requestHeaders,
        requestBodyPlaintext: plaintext,
        requestBodyEncrypted: encrypted,
        responseHeaders,
        responseBodyEncrypted: response.body.payload,
        responseBodyDecrypted: decrypted
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
    if (!this.state.session || !this.state.accessToken) {
      throw new Error('Run steps 1-3 first');
    }

    const start = Date.now();

    try {
      this.state.session = await this.wasmService.initSession(
        this.config.sidecarUrl,
        this.config.clientId,
        this.state.accessToken,
        this.config.subject
      );

      this.state.session.save_to_storage();

      return {
        step: 4,
        name: 'Session Refresh (Authenticated ECDH)',
        success: true,
        durationMs: Date.now() - start,
        sessionId: this.state.session.session_id,
        kid: this.state.session.kid,
        authenticated: this.state.session.authenticated,
        expiresInSec: this.state.session.expires_in_sec,
        storageNote: '✅ Session key refreshed and re-encrypted in sessionStorage'
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
    if (!this.state.session || !this.state.refreshToken) {
      throw new Error('Run steps 1-4 first');
    }

    const start = Date.now();
    const timestamp = Date.now().toString();
    const nonce = this.wasmService.generateNonce();

    const requestBody = {
      grant_type: 'refresh_token',
      refresh_token: this.state.refreshToken
    };

    const plaintext = JSON.stringify(requestBody);
    const encrypted = this.state.session.encrypt(plaintext, timestamp, nonce);

    const requestHeaders = {
      'Content-Type': 'application/json',
      'X-ClientId': this.config.clientId,
      'X-Idempotency-Key': `${timestamp}.${nonce}`,
      'X-Kid': this.state.session.kid,
      'Authorization': `Bearer ${this.state.accessToken}`
    };

    try {
      const response = await firstValueFrom(
        this.http.post<any>(
          `${this.config.sidecarUrl}/api/v1/token`,
          { payload: encrypted },
          { headers: requestHeaders, observe: 'response' }
        )
      );

      const responseHeaders = {
        'x-kid': response.headers.get('x-kid'),
        'x-idempotency-key': response.headers.get('x-idempotency-key'),
        'content-type': response.headers.get('content-type')
      };

      const respIdempKey = response.headers.get('X-Idempotency-Key') || '';
      const [respTimestamp, respNonce] = respIdempKey.split('.');
      const decrypted = this.state.session.decrypt(response.body.payload, respTimestamp, respNonce);
      const tokens = JSON.parse(decrypted);

      this.state.accessToken = tokens.access_token;
      this.state.refreshToken = tokens.refresh_token;

      return {
        step: 5,
        name: 'Token Refresh (Bearer + GCM)',
        success: true,
        durationMs: Date.now() - start,
        requestHeaders,
        requestBodyPlaintext: plaintext,
        requestBodyEncrypted: encrypted,
        responseHeaders,
        responseBodyEncrypted: response.body.payload,
        responseBodyDecrypted: decrypted
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
    if (!this.state.session || !this.state.refreshToken) {
      throw new Error('Run steps 1-5 first');
    }

    const start = Date.now();
    const timestamp = Date.now().toString();
    const nonce = this.wasmService.generateNonce();

    const requestBody = {
      token: this.state.refreshToken,
      token_type_hint: 'refresh_token'
    };

    const plaintext = JSON.stringify(requestBody);
    const encrypted = this.state.session.encrypt(plaintext, timestamp, nonce);

    const requestHeaders = {
      'Content-Type': 'application/json',
      'X-ClientId': this.config.clientId,
      'X-Idempotency-Key': `${timestamp}.${nonce}`,
      'X-Kid': this.state.session.kid,
      'Authorization': `Bearer ${this.state.accessToken}`
    };

    try {
      const response = await firstValueFrom(
        this.http.post<any>(
          `${this.config.sidecarUrl}/api/v1/revoke`,
          { payload: encrypted },
          { headers: requestHeaders, observe: 'response' }
        )
      );

      const responseHeaders = {
        'x-kid': response.headers.get('x-kid'),
        'x-idempotency-key': response.headers.get('x-idempotency-key'),
        'content-type': response.headers.get('content-type')
      };

      const respIdempKey = response.headers.get('X-Idempotency-Key') || '';
      const [respTimestamp, respNonce] = respIdempKey.split('.');

      let decrypted = '';
      if (response.body && response.body.payload) {
        decrypted = this.state.session.decrypt(response.body.payload, respTimestamp, respNonce);
      }

      // Clear session from storage and reset state
      this.wasmService.clearSessionStorage();
      this.state.session = null;
      this.state.accessToken = '';
      this.state.refreshToken = '';

      return {
        step: 6,
        name: 'Token Revocation (Bearer + GCM)',
        success: true,
        durationMs: Date.now() - start,
        requestHeaders,
        requestBodyPlaintext: plaintext,
        requestBodyEncrypted: encrypted,
        responseHeaders,
        responseBodyEncrypted: response.body?.payload || '',
        responseBodyDecrypted: decrypted || '(empty)',
        storageNote: '✅ Session cleared from sessionStorage'
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
    this.state.accessToken = '';
    this.state.refreshToken = '';
  }
}

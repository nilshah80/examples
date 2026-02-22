import { Injectable } from '@angular/core';

declare global {
  function init(module_or_path?: any): Promise<any>;
  function init_session(
    sidecarUrl: string,
    clientId: string,
    accessToken?: string,
    subject?: string
  ): Promise<any>;
  function get_sidecar_url(): string;
  function get_client_id(): string;
  function get_subject(): string;
  class SessionContext {
    session_id: string;
    kid: string;
    authenticated: boolean;
    expires_in_sec: number;
    encrypt(plaintext: string, timestamp: string, nonce: string): string;
    decrypt(ciphertext: string, timestamp: string, nonce: string): string;
    issue_token(request_body_json: string): Promise<string>;
    introspect_token(): Promise<string>;
    refresh_session(): Promise<SessionContext>;
    refresh_tokens(): Promise<string>;
    revoke_tokens(): Promise<string>;
    save_to_storage(): void;
    static load_from_storage(): SessionContext;
    static clear_storage(): void;
  }
}

@Injectable({
  providedIn: 'root'
})
export class WasmService {
  private wasmLoaded = false;

  async loadWasm(): Promise<void> {
    if (this.wasmLoaded) return;

    try {
      // Import the WASM module
      const wasmModule = await import('../assets/wasm/rust_wasm_angular_internal.js');

      // Initialize with object parameter (new wasm-bindgen format)
      await wasmModule.default({ module_or_path: '/assets/wasm/rust_wasm_angular_internal_bg.wasm' });

      // Copy functions to global scope
      (window as any).init_session = wasmModule.init_session;
      (window as any).get_sidecar_url = wasmModule.get_sidecar_url;
      (window as any).get_client_id = wasmModule.get_client_id;
      (window as any).get_subject = wasmModule.get_subject;
      (window as any).SessionContext = wasmModule.SessionContext;

      this.wasmLoaded = true;
      console.log('✅ WASM module loaded successfully');
    } catch (error) {
      console.error('❌ Failed to load WASM module:', error);
      throw error;
    }
  }

  getSidecarUrl(): string {
    return (window as any).get_sidecar_url();
  }

  getClientId(): string {
    return (window as any).get_client_id();
  }

  getSubject(): string {
    return (window as any).get_subject();
  }

  async initSession(
    sidecarUrl: string,
    clientId: string,
    accessToken?: string,
    subject?: string
  ): Promise<any> {
    return await (window as any).init_session(sidecarUrl, clientId, accessToken, subject);
  }

  loadSessionFromStorage(): any | null {
    try {
      return (window as any).SessionContext.load_from_storage();
    } catch {
      return null;
    }
  }

  clearSessionStorage(): void {
    (window as any).SessionContext.clear_storage();
  }
}

import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class WasmService {
  private wasmLoaded = false;
  private wasmModule: any = null;

  async loadWasm(): Promise<void> {
    if (this.wasmLoaded) return;

    try {
      // Use fetch to load the WASM module (bypass Vite's import resolution)
      // Add timestamp to bust cache
      const timestamp = Date.now();
      const response = await fetch(`/wasm/rust_wasm_angular_external.js?t=${timestamp}`);
      const moduleText = await response.text();

      // Create a blob URL for the module
      const blob = new Blob([moduleText], { type: 'application/javascript' });
      const moduleUrl = URL.createObjectURL(blob);

      // Import the module dynamically
      this.wasmModule = await import(/* @vite-ignore */ moduleUrl);

      // Initialize WASM with object parameter (new wasm-bindgen format)
      await this.wasmModule.default({ module_or_path: `/wasm/rust_wasm_angular_external_bg.wasm?t=${timestamp}` });

      this.wasmLoaded = true;
      console.log('✅ WASM module loaded successfully');
      console.log('🔧 WASM Config loaded:', {
        sidecarUrl: this.wasmModule.get_sidecar_url(),
        clientId: this.wasmModule.get_client_id(),
        subject: this.wasmModule.get_subject()
      });
    } catch (error) {
      console.error('❌ Failed to load WASM module:', error);
      throw error;
    }
  }

  getSidecarUrl(): string {
    return this.wasmModule.get_sidecar_url();
  }

  getClientId(): string {
    return this.wasmModule.get_client_id();
  }

  getClientSecret(): string {
    return this.wasmModule.get_client_secret();
  }

  getSubject(): string {
    return this.wasmModule.get_subject();
  }

  generateNonce(): string {
    return this.wasmModule.generate_nonce();
  }

  computeHmacSignature(
    method: string,
    path: string,
    timestamp: string,
    nonce: string,
    body: string,
    secret: string
  ): string {
    return this.wasmModule.compute_hmac_signature(
      method,
      path,
      timestamp,
      nonce,
      body,
      secret
    );
  }

  async initSession(
    sidecarUrl: string,
    clientId: string,
    accessToken?: string,
    subject?: string
  ): Promise<any> {
    return await this.wasmModule.init_session(sidecarUrl, clientId, accessToken, subject);
  }

  loadSessionFromStorage(): any | null {
    try {
      return this.wasmModule.SessionContext.load_from_storage();
    } catch {
      return null;
    }
  }

  clearSessionStorage(): void {
    this.wasmModule.SessionContext.clear_storage();
  }
}

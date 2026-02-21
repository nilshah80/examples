declare module '../assets/wasm/rust_wasm_angular_external.js' {
  export default function init(module_or_path?: any): Promise<any>;
  export function init_session(
    sidecarUrl: string,
    clientId: string,
    accessToken?: string,
    subject?: string
  ): Promise<any>;
  export function generate_nonce(): string;
  export function compute_hmac_signature(
    method: string,
    path: string,
    timestamp: string,
    nonce: string,
    body: string,
    secret: string
  ): string;
  export function get_sidecar_url(): string;
  export function get_client_id(): string;
  export function get_client_secret(): string;
  export function get_subject(): string;
  export class SessionContext {
    session_id: string;
    kid: string;
    authenticated: boolean;
    expires_in_sec: number;
    encrypt(plaintext: string, timestamp: string, nonce: string): string;
    decrypt(ciphertext: string, timestamp: string, nonce: string): string;
    save_to_storage(): void;
    static load_from_storage(): SessionContext;
    static clear_storage(): void;
  }
}

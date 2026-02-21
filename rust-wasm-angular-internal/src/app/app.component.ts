import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { IdentityService, StepResult } from './identity.service';

interface Step {
  n: number;
  title: string;
  desc: string;
  endpoint: string;
  session: boolean;
}

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements OnInit {
  title = 'Identity Service — Rust WASM Angular (Internal Client)';
  loading = true;
  error: string | null = null;
  config: any = {};

  steps: Step[] = [
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
      desc: 'Encrypt token request with session key. Returns access + refresh tokens.',
      endpoint: 'POST /api/v1/token/issue',
      session: false
    },
    {
      n: 3,
      title: 'Token Introspection (Bearer + GCM)',
      desc: 'Verify access token is valid and extract claims.',
      endpoint: 'POST /api/v1/token/introspect',
      session: false
    },
    {
      n: 4,
      title: 'Session Refresh (Authenticated ECDH)',
      desc: 'Create new authenticated session using access token. Extends session TTL.',
      endpoint: 'POST /api/v1/session/refresh',
      session: true
    },
    {
      n: 5,
      title: 'Token Refresh (Bearer + GCM)',
      desc: 'Use refresh token to get new access token.',
      endpoint: 'POST /api/v1/token/refresh',
      session: false
    },
    {
      n: 6,
      title: 'Token Revocation (Bearer + GCM)',
      desc: 'Revoke refresh token and clear session from sessionStorage.',
      endpoint: 'POST /api/v1/token/revoke',
      session: false
    }
  ];

  results: Map<number, StepResult> = new Map();
  currentStep: number | null = null;
  nextAllowedStep: number = 1;

  constructor(private identityService: IdentityService) {}

  async ngOnInit() {
    try {
      await this.identityService.initialize();
      this.config = this.identityService.getConfig();
      this.loading = false;
    } catch (error: any) {
      this.error = `Failed to initialize: ${error.message}`;
      this.loading = false;
    }
  }

  async runStep(stepNum: number) {
    this.currentStep = stepNum;
    this.results.delete(stepNum);

    try {
      let result: StepResult;
      switch (stepNum) {
        case 1:
          result = await this.identityService.step1();
          break;
        case 2:
          result = await this.identityService.step2();
          break;
        case 3:
          result = await this.identityService.step3();
          break;
        case 4:
          result = await this.identityService.step4();
          break;
        case 5:
          result = await this.identityService.step5();
          break;
        case 6:
          result = await this.identityService.step6();
          break;
        default:
          return;
      }

      this.results.set(stepNum, result);

      // Enable next step on success
      if (result.success && stepNum === this.nextAllowedStep) {
        this.nextAllowedStep = stepNum + 1;
      }
    } catch (error: any) {
      this.results.set(stepNum, {
        step: stepNum,
        name: this.steps[stepNum - 1].title,
        success: false,
        durationMs: 0,
        error: error.message || String(error)
      });
    } finally {
      this.currentStep = null;
    }
  }

  reset() {
    this.identityService.reset();
    this.results.clear();
    this.nextAllowedStep = 1;
  }

  getResult(stepNum: number): StepResult | undefined {
    return this.results.get(stepNum);
  }

  isStepRunning(stepNum: number): boolean {
    return this.currentStep === stepNum;
  }

  canRunStep(stepNum: number): boolean {
    return stepNum === this.nextAllowedStep;
  }

  isStepDisabled(stepNum: number): boolean {
    return this.isStepRunning(stepNum) || !this.canRunStep(stepNum);
  }

  truncate(text: string | undefined, maxLength: number = 100): string {
    if (!text) return '';
    return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
  }

  formatJson(json: string | undefined): string {
    if (!json) return '';
    try {
      return JSON.stringify(JSON.parse(json), null, 2);
    } catch {
      return json;
    }
  }

  formatHeaders(headers: any): string {
    if (!headers) return '';
    return Object.entries(headers)
      .map(([key, value]) => `${key}: ${value}`)
      .join('\n');
  }
}

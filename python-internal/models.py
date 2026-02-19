from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SessionContext:
    session_id: str
    session_key: bytearray
    kid: str
    client_id: str
    authenticated: bool
    expires_in_sec: int

    def zeroize(self):
        for i in range(len(self.session_key)):
            self.session_key[i] = 0


@dataclass
class StepResult:
    step: int
    name: str
    request_headers: dict = field(default_factory=dict)
    request_body_plaintext: str = ""
    request_body_encrypted: str = ""
    response_headers: dict = field(default_factory=dict)
    response_body_encrypted: str = ""
    response_body_decrypted: str = ""
    duration_ms: int = 0
    success: bool = False
    error: str | None = None

    def to_dict(self) -> dict:
        d = {
            "step": self.step,
            "name": self.name,
            "requestHeaders": self.request_headers,
            "requestBodyPlaintext": self.request_body_plaintext,
            "requestBodyEncrypted": self.request_body_encrypted,
            "responseHeaders": self.response_headers,
            "responseBodyEncrypted": self.response_body_encrypted,
            "responseBodyDecrypted": self.response_body_decrypted,
            "durationMs": self.duration_ms,
            "success": self.success,
        }
        if self.error is not None:
            d["error"] = self.error
        return d


@dataclass
class SessionResult:
    step: int
    name: str
    success: bool
    duration_ms: int = 0
    session_id: str = ""
    kid: str = ""
    authenticated: bool = False
    expires_in_sec: int = 0
    error: str | None = None

    def to_dict(self) -> dict:
        d = {
            "step": self.step,
            "name": self.name,
            "success": self.success,
            "durationMs": self.duration_ms,
            "sessionId": self.session_id,
            "kid": self.kid,
            "authenticated": self.authenticated,
            "expiresInSec": self.expires_in_sec,
        }
        if self.error is not None:
            d["error"] = self.error
        return d

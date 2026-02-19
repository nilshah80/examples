package main

// SessionContext holds the derived session state.
type SessionContext struct {
	SessionID     string
	SessionKey    [32]byte
	Kid           string
	ClientID      string
	Authenticated bool
	ExpiresInSec  int64
}

// Zeroize clears the session key.
func (s *SessionContext) Zeroize() {
	for i := range s.SessionKey {
		s.SessionKey[i] = 0
	}
}

// StepResult is the JSON response for steps 2,3,5,6.
type StepResult struct {
	Step                  int               `json:"step"`
	Name                  string            `json:"name"`
	RequestHeaders        map[string]string `json:"requestHeaders"`
	RequestBodyPlaintext  string            `json:"requestBodyPlaintext"`
	RequestBodyEncrypted  string            `json:"requestBodyEncrypted"`
	ResponseHeaders       map[string]string `json:"responseHeaders"`
	ResponseBodyEncrypted string            `json:"responseBodyEncrypted"`
	ResponseBodyDecrypted string            `json:"responseBodyDecrypted"`
	DurationMs            int64             `json:"durationMs"`
	Success               bool              `json:"success"`
	Error                 *string           `json:"error,omitempty"`
}

// SessionResult is the JSON response for steps 1 and 4.
type SessionResult struct {
	Step          int     `json:"step"`
	Name          string  `json:"name"`
	Success       bool    `json:"success"`
	DurationMs    int64   `json:"durationMs"`
	SessionID     string  `json:"sessionId"`
	Kid           string  `json:"kid"`
	Authenticated bool    `json:"authenticated"`
	ExpiresInSec  int64   `json:"expiresInSec"`
	Error         *string `json:"error,omitempty"`
}

// -- API DTOs --

type SessionInitRequest struct {
	ClientPublicKey string `json:"clientPublicKey"`
}

type SessionInitResponse struct {
	SessionID       string `json:"sessionId"`
	ServerPublicKey string `json:"serverPublicKey"`
	EncAlg          string `json:"encAlg,omitempty"`
	ExpiresInSec    int64  `json:"expiresInSec"`
}

type EncryptedPayload struct {
	Payload string `json:"payload"`
}

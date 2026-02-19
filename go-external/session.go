package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// InitSession performs Step 1: Anonymous ECDH session init.
func InitSession(config *Config, httpClient *http.Client) (*SessionContext, error) {
	keyPair, err := generateEcdhKeyPair()
	if err != nil {
		return nil, err
	}
	pubKeyBytes := exportPublicKey(keyPair)
	nonce := generateNonce()
	ts := millisNow()

	body := SessionInitRequest{
		ClientPublicKey: toBase64(pubKeyBytes),
	}
	bodyJSON, _ := json.Marshal(body)

	url := fmt.Sprintf("%s/api/v1/session/init", config.SidecarURL)
	req, err := http.NewRequest("POST", url, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("session init request creation failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Idempotency-Key", fmt.Sprintf("%s.%s", ts, nonce))
	req.Header.Set("X-Clientid", config.ClientID)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("session init request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("session init failed: HTTP %d — %s", resp.StatusCode, string(respBody))
	}

	var data SessionInitResponse
	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, fmt.Errorf("failed to parse session init response: %w", err)
	}

	return deriveSession(keyPair, &data, config.ClientID, false)
}

// RefreshSession performs Step 4: Authenticated session refresh with Bearer + X-Subject.
func RefreshSession(config *Config, httpClient *http.Client, accessToken string, oldSession *SessionContext) (*SessionContext, error) {
	keyPair, err := generateEcdhKeyPair()
	if err != nil {
		return nil, err
	}
	pubKeyBytes := exportPublicKey(keyPair)
	nonce := generateNonce()
	ts := millisNow()

	body := SessionInitRequest{
		ClientPublicKey: toBase64(pubKeyBytes),
	}
	bodyJSON, _ := json.Marshal(body)

	url := fmt.Sprintf("%s/api/v1/session/init", config.SidecarURL)
	req, err := http.NewRequest("POST", url, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("session refresh request creation failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("X-Subject", config.Subject)
	req.Header.Set("X-Idempotency-Key", fmt.Sprintf("%s.%s", ts, nonce))
	req.Header.Set("X-Clientid", config.ClientID)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("session refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	// Zeroize old session key
	if oldSession != nil {
		oldSession.Zeroize()
	}

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("session refresh failed: HTTP %d — %s", resp.StatusCode, string(respBody))
	}

	var data SessionInitResponse
	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, fmt.Errorf("failed to parse session refresh response: %w", err)
	}

	return deriveSession(keyPair, &data, config.ClientID, true)
}

func deriveSession(keyPair *EcdhKeyPair, data *SessionInitResponse, clientID string, authenticated bool) (*SessionContext, error) {
	shared, err := computeSharedSecret(keyPair, data.ServerPublicKey)
	if err != nil {
		return nil, err
	}
	sessionKey, err := deriveSessionKey(shared, data.SessionID, clientID)
	if err != nil {
		return nil, err
	}

	return &SessionContext{
		SessionID:     data.SessionID,
		SessionKey:    sessionKey,
		Kid:           fmt.Sprintf("session:%s", data.SessionID),
		ClientID:      clientID,
		Authenticated: authenticated,
		ExpiresInSec:  data.ExpiresInSec,
	}, nil
}

func millisNow() string {
	return fmt.Sprintf("%d", time.Now().UnixMilli())
}

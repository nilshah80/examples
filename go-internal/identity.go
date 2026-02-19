package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// IssueToken performs Step 2: Token Issue (Basic Auth + GCM).
func IssueToken(config *Config, httpClient *http.Client, session *SessionContext, plaintext string) StepResult {
	basicAuth := fmt.Sprintf("Basic %s",
		base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", config.ClientID, config.ClientSecret))))
	auth := map[string]string{"Authorization": basicAuth}

	return postEncrypted(config, httpClient, "/v1/token/issue", session, plaintext, auth, 2, "Token Issue (Basic Auth + GCM)")
}

// IntrospectToken performs Step 3: Token Introspection (Bearer + GCM).
func IntrospectToken(config *Config, httpClient *http.Client, session *SessionContext, plaintext, accessToken string) StepResult {
	auth := map[string]string{"Authorization": fmt.Sprintf("Bearer %s", accessToken)}
	return postEncrypted(config, httpClient, "/v1/introspect", session, plaintext, auth, 3, "Token Introspection (Bearer + GCM)")
}

// RefreshToken performs Step 5: Token Refresh (Bearer + GCM).
func RefreshToken(config *Config, httpClient *http.Client, session *SessionContext, plaintext, accessToken string) StepResult {
	auth := map[string]string{"Authorization": fmt.Sprintf("Bearer %s", accessToken)}
	return postEncrypted(config, httpClient, "/v1/token", session, plaintext, auth, 5, "Token Refresh (Bearer + GCM)")
}

// RevokeToken performs Step 6: Token Revocation (Bearer + GCM).
func RevokeToken(config *Config, httpClient *http.Client, session *SessionContext, plaintext, accessToken string) StepResult {
	auth := map[string]string{"Authorization": fmt.Sprintf("Bearer %s", accessToken)}
	return postEncrypted(config, httpClient, "/v1/revoke", session, plaintext, auth, 6, "Token Revocation (Bearer + GCM)")
}

// postEncrypted: core encrypted POST — encrypt request, send, decrypt response.
func postEncrypted(config *Config, httpClient *http.Client, path string, session *SessionContext, plaintext string, authHeaders map[string]string, stepNum int, stepName string) StepResult {
	start := time.Now()

	nonce := generateNonce()
	ts := millisNow()
	aad := buildAAD(ts, nonce, session.Kid, session.ClientID)

	encrypted, err := gcmEncrypt(plaintext, session.SessionKey, aad)
	if err != nil {
		return errorResult(stepNum, stepName, plaintext, start, err.Error())
	}

	headers := map[string]string{
		"Content-Type":      "application/json",
		"X-Kid":             session.Kid,
		"X-Idempotency-Key": fmt.Sprintf("%s.%s", ts, nonce),
		"X-Clientid":        session.ClientID,
	}
	for k, v := range authHeaders {
		headers[k] = v
	}

	requestBody, _ := json.Marshal(EncryptedPayload{Payload: encrypted})

	url := fmt.Sprintf("%s/api%s", config.SidecarURL, path)
	req, err := http.NewRequest("POST", url, strings.NewReader(string(requestBody)))
	if err != nil {
		return errorResult(stepNum, stepName, plaintext, start, err.Error())
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return errorResult(stepNum, stepName, plaintext, start, err.Error())
	}
	defer resp.Body.Close()

	respHeaders := extractResponseHeaders(resp)
	respBodyBytes, _ := io.ReadAll(resp.Body)
	responseBodyStr := string(respBodyBytes)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return StepResult{
			Step:                  stepNum,
			Name:                  stepName,
			RequestHeaders:        headers,
			RequestBodyPlaintext:  plaintext,
			RequestBodyEncrypted:  encrypted,
			ResponseHeaders:       respHeaders,
			ResponseBodyEncrypted: "",
			ResponseBodyDecrypted: responseBodyStr,
			DurationMs:            time.Since(start).Milliseconds(),
			Success:               false,
			Error:                 strPtr(fmt.Sprintf("HTTP %d: %s", resp.StatusCode, responseBodyStr)),
		}
	}

	respEncrypted, decrypted := decryptResponse(responseBodyStr, respHeaders, session)

	return StepResult{
		Step:                  stepNum,
		Name:                  stepName,
		RequestHeaders:        headers,
		RequestBodyPlaintext:  plaintext,
		RequestBodyEncrypted:  encrypted,
		ResponseHeaders:       respHeaders,
		ResponseBodyEncrypted: respEncrypted,
		ResponseBodyDecrypted: decrypted,
		DurationMs:            time.Since(start).Milliseconds(),
		Success:               true,
		Error:                 nil,
	}
}

func decryptResponse(responseBody string, respHeaders map[string]string, session *SessionContext) (string, string) {
	respKid, hasKid := respHeaders["x-kid"]
	respIdemp, hasIdemp := respHeaders["x-idempotency-key"]

	if hasKid && hasIdemp {
		parts := strings.SplitN(respIdemp, ".", 2)
		if len(parts) == 2 {
			respAAD := buildAAD(parts[0], parts[1], respKid, session.ClientID)
			var payload EncryptedPayload
			if err := json.Unmarshal([]byte(responseBody), &payload); err == nil {
				if decrypted, err := gcmDecrypt(payload.Payload, session.SessionKey, respAAD); err == nil {
					return payload.Payload, decrypted
				}
			}
		}
	}
	return "", responseBody
}

func extractResponseHeaders(resp *http.Response) map[string]string {
	headers := make(map[string]string)
	for _, key := range []string{"x-kid", "x-idempotency-key", "content-type"} {
		if val := resp.Header.Get(key); val != "" {
			headers[key] = val
		}
	}
	return headers
}

func errorResult(stepNum int, stepName, plaintext string, start time.Time, errMsg string) StepResult {
	return StepResult{
		Step:                  stepNum,
		Name:                  stepName,
		RequestHeaders:        map[string]string{},
		RequestBodyPlaintext:  plaintext,
		RequestBodyEncrypted:  "",
		ResponseHeaders:       map[string]string{},
		ResponseBodyEncrypted: "",
		ResponseBodyDecrypted: "",
		DurationMs:            time.Since(start).Milliseconds(),
		Success:               false,
		Error:                 strPtr(errMsg),
	}
}

func strPtr(s string) *string {
	return &s
}

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// ComputeSignature computes HMAC-SHA256 signature for external client auth.
//
// 1. bodyHash = SHA-256(plaintext).hex().lowercase()
// 2. stringToSign = "POST\n{path}\n{timestamp}\n{nonce}\n{bodyHash}"
// 3. signature = HMAC-SHA256(secret, stringToSign).hex().lowercase()
func ComputeSignature(method, path, timestamp, nonce, body, secret string) string {
	bodyHashBytes := sha256.Sum256([]byte(body))
	bodyHash := hex.EncodeToString(bodyHashBytes[:])

	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s\n%s",
		strings.ToUpper(method), path, timestamp, nonce, bodyHash)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(stringToSign))
	return hex.EncodeToString(mac.Sum(nil))
}

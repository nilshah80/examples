package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
)

// EcdhKeyPair holds the ECDH P-256 private key.
type EcdhKeyPair struct {
	PrivateKey *ecdh.PrivateKey
}

// -- Base64 --

func toBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func fromBase64(b64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(b64)
}

// -- Nonce --

func generateNonce() string {
	return uuid.New().String()
}

// -- ECDH P-256 --

func generateEcdhKeyPair() (*EcdhKeyPair, error) {
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ECDH key generation failed: %w", err)
	}
	return &EcdhKeyPair{PrivateKey: privateKey}, nil
}

// exportPublicKey returns the 65-byte uncompressed public key (0x04 || X(32) || Y(32)).
func exportPublicKey(kp *EcdhKeyPair) []byte {
	return kp.PrivateKey.PublicKey().Bytes()
}

// computeSharedSecret computes the ECDH shared secret from our keypair
// and peer's base64-encoded 65-byte uncompressed public key.
func computeSharedSecret(kp *EcdhKeyPair, peerPublicKeyBase64 string) ([]byte, error) {
	peerBytes, err := fromBase64(peerPublicKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 peer key: %w", err)
	}
	peerPubKey, err := ecdh.P256().NewPublicKey(peerBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid EC point: %w", err)
	}
	shared, err := kp.PrivateKey.ECDH(peerPubKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}
	return shared, nil
}

// -- HKDF-SHA256 --

// deriveSessionKey derives a 32-byte AES-256 session key using HKDF-SHA256.
// salt = UTF-8(sessionId), info = UTF-8("SESSION|A256GCM|{clientId}")
func deriveSessionKey(sharedSecret []byte, sessionID, clientID string) ([32]byte, error) {
	salt := []byte(sessionID)
	info := []byte(fmt.Sprintf("SESSION|A256GCM|%s", clientID))

	hkdfReader := hkdf.New(sha256.New, sharedSecret, salt, info)

	var sessionKey [32]byte
	if _, err := io.ReadFull(hkdfReader, sessionKey[:]); err != nil {
		return [32]byte{}, fmt.Errorf("HKDF expand failed: %w", err)
	}

	// Zeroize shared secret
	for i := range sharedSecret {
		sharedSecret[i] = 0
	}

	return sessionKey, nil
}

// -- AES-256-GCM --

// gcmEncrypt performs AES-256-GCM encryption.
// Returns base64(IV(12) || ciphertext || tag(16)).
func gcmEncrypt(plaintext string, sessionKey [32]byte, aad []byte) (string, error) {
	block, err := aes.NewCipher(sessionKey[:])
	if err != nil {
		return "", fmt.Errorf("AES key error: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM error: %w", err)
	}

	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("IV generation failed: %w", err)
	}

	// Seal appends ciphertext+tag to dst (iv here), so result = iv || ciphertext || tag
	sealed := gcm.Seal(iv, iv, []byte(plaintext), aad)

	return toBase64(sealed), nil
}

// gcmDecrypt performs AES-256-GCM decryption.
// Input: base64(IV(12) || ciphertext || tag(16)).
func gcmDecrypt(ciphertextBase64 string, sessionKey [32]byte, aad []byte) (string, error) {
	encrypted, err := fromBase64(ciphertextBase64)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %w", err)
	}
	if len(encrypted) < 28 {
		return "", fmt.Errorf("ciphertext too short")
	}

	block, err := aes.NewCipher(sessionKey[:])
	if err != nil {
		return "", fmt.Errorf("AES key error: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM error: %w", err)
	}

	iv := encrypted[:12]
	ciphertext := encrypted[12:]

	plainBytes, err := gcm.Open(nil, iv, ciphertext, aad)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return string(plainBytes), nil
}

// -- AAD --

// buildAAD constructs AAD: "timestamp|nonce|kid|clientId" as UTF-8 bytes.
func buildAAD(timestamp, nonce, kid, clientID string) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%s", timestamp, nonce, kid, clientID))
}

package firebasetunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

// deriveKey turns an arbitrary-length PSK string into a 32-byte AES-256 key.
// This is a simple SHA-256 KDF, sufficient for a pre-shared-secret use case
// (not a password — operators are expected to provide a high-entropy PSK).
func deriveKey(psk string) [32]byte {
	return sha256.Sum256([]byte(psk))
}

// encryptPayload encrypts data with AES-256-GCM under key, prefixing the
// nonce to the ciphertext.
func encryptPayload(key [32]byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

// decryptPayload reverses encryptPayload. Returns an error (without
// distinguishing "bad key" from "corrupt data") if authentication fails —
// callers should treat any error here as an auth/abuse signal.
func decryptPayload(key [32]byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, fmt.Errorf("firebasetunnel: ciphertext too short")
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

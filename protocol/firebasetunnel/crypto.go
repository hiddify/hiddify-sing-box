package firebasetunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

const hmacTagLen = 16

// deriveKey turns an arbitrary-length PSK string into a 32-byte AES-256 key.
// This is a simple SHA-256 KDF, sufficient for a pre-shared-secret use case
// (not a password — operators are expected to provide a high-entropy PSK).
func deriveKey(psk string) [32]byte {
	return sha256.Sum256([]byte(psk))
}

// deriveHMACKey derives a 32-byte HMAC key from the raw Firebase secret.
// Used for integrity verification on the unencrypted (no-PSK) path.
func deriveHMACKey(secret string) []byte {
	h := sha256.Sum256(append([]byte("hmac:"), []byte(secret)...))
	return h[:]
}

// hmacTag returns a hmacTagLen-byte HMAC-SHA256 tag over payload, keyed by secretKey.
func hmacTag(secretKey []byte, payload []byte) []byte {
	mac := hmac.New(sha256.New, secretKey)
	mac.Write(payload)
	return mac.Sum(nil)[:hmacTagLen]
}

// appendHMACTag appends a hmacTagLen-byte HMAC tag to payload and returns
// the combined slice (no allocation if capacity permits).
func appendHMACTag(secretKey []byte, payload []byte) []byte {
	tag := hmacTag(secretKey, payload)
	return append(payload, tag...)
}

// verifyAndStripHMACTag verifies the hmacTagLen-byte tag appended to data
// and returns the payload without the tag. Returns an error on mismatch —
// treat as integrity failure / potential abuse signal.
func verifyAndStripHMACTag(secretKey []byte, data []byte) ([]byte, error) {
	if len(data) < hmacTagLen {
		return nil, fmt.Errorf("firebasetunnel: HMAC tag missing (data too short)")
	}
	payload := data[:len(data)-hmacTagLen]
	got := data[len(data)-hmacTagLen:]
	expected := hmacTag(secretKey, payload)
	if !hmac.Equal(got, expected) {
		return nil, fmt.Errorf("firebasetunnel: HMAC verification failed — data integrity compromised")
	}
	return payload, nil
}

// encryptPayloadAAD encrypts data with AES-256-GCM under key, binding aad as
// additional authenticated data. Nonce is prepended to the ciphertext.
// If aad is nil, no additional data is bound (same as old encryptPayload).
func encryptPayloadAAD(key [32]byte, data []byte, aad []byte) ([]byte, error) {
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
	return gcm.Seal(nonce, nonce, data, aad), nil
}

// decryptPayloadAAD reverses encryptPayloadAAD. aad must match what was
// passed to encryptPayloadAAD exactly; mismatch causes an auth error.
func decryptPayloadAAD(key [32]byte, data []byte, aad []byte) ([]byte, error) {
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
	return gcm.Open(nil, nonce, ciphertext, aad)
}

// encryptPayload encrypts with no additional authenticated data.
// Kept for backward compatibility with existing tests.
func encryptPayload(key [32]byte, data []byte) ([]byte, error) {
	return encryptPayloadAAD(key, data, nil)
}

// decryptPayload decrypts with no additional authenticated data.
// Kept for backward compatibility with existing tests.
func decryptPayload(key [32]byte, data []byte) ([]byte, error) {
	return decryptPayloadAAD(key, data, nil)
}

// chunkAAD builds the AEAD additional data for a chunk: encodes sessionID,
// direction ("c2s"/"s2c"), and seq into a compact binary blob so that a chunk
// from one session/direction/position cannot be replayed into another.
func chunkAAD(sessionID, direction string, seq uint64) []byte {
	seqBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(seqBuf, seq)
	aad := make([]byte, 0, len(sessionID)+1+len(direction)+1+8)
	aad = append(aad, []byte(sessionID)...)
	aad = append(aad, '/')
	aad = append(aad, []byte(direction)...)
	aad = append(aad, '/')
	aad = append(aad, seqBuf...)
	return aad
}

package firebasetunnel

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := deriveKey("test-psk")
	data := []byte("secret payload bytes")

	ct, err := encryptPayload(key, data)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Equal(ct, data) {
		t.Fatal("ciphertext must not equal plaintext")
	}

	pt, err := decryptPayload(key, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(pt, data) {
		t.Fatalf("decrypted mismatch: got %q want %q", pt, data)
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	key := deriveKey("psk-a")
	wrongKey := deriveKey("psk-b")
	ct, err := encryptPayload(key, []byte("data"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := decryptPayload(wrongKey, ct); err == nil {
		t.Fatal("expected decrypt failure with wrong key")
	}
}

func TestDecryptTruncatedFails(t *testing.T) {
	key := deriveKey("psk")
	if _, err := decryptPayload(key, []byte("x")); err == nil {
		t.Fatal("expected error for truncated ciphertext")
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	a := deriveKey("same-psk")
	b := deriveKey("same-psk")
	if a != b {
		t.Fatal("deriveKey must be deterministic for the same input")
	}
	c := deriveKey("different-psk")
	if a == c {
		t.Fatal("deriveKey must differ for different input")
	}
}

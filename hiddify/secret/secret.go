// Package secret decrypts values that were encrypted with the build-time key.
//
// The key is embedded at build time (CI secret HIDDIFY_SECRET_KEY):
//
//	-ldflags "-X github.com/sagernet/sing-box/hiddify/secret.Key=<base64 AES-256 key>"
//
// An encrypted value is base64(nonce || AES-256-GCM ciphertext) of "henc:" + plaintext, so it looks
// like any other base64 value; it counts as encrypted only if it decrypts and starts with the marker.
// The key ships inside the binary, so this keeps embedded configs out of plain sight; it is not
// protection against someone who extracts the key from the binary.
package secret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// Key is the base64-encoded AES-256 key, set at build time; empty in builds without it.
var Key string

// marker prefixes the plaintext before encryption; finding it after decryption proves the value
// was encrypted with this key.
const marker = "henc:"

func DecodeKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, E.Cause(err, "decode key")
	}
	if len(key) != 32 {
		return nil, E.New("key must be 32 bytes (AES-256), got ", len(key))
	}
	return key, nil
}

// Encrypt encrypts plaintext with a base64-encoded AES-256 key (used by the build tool).
func Encrypt(encodedKey string, plaintext []byte) (string, error) {
	gcm, err := newGCM(encodedKey)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, append([]byte(marker), plaintext...), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// TryDecrypt decrypts value with the embedded Key. ok is false when the value is not encrypted
// with it (no key in this build, not base64, does not decrypt, or no marker): use it as it is.
func TryDecrypt(value string) (plaintext []byte, ok bool) {
	return TryDecryptWithKey(Key, value)
}

func TryDecryptWithKey(encodedKey, value string) (plaintext []byte, ok bool) {
	if encodedKey == "" {
		return nil, false
	}
	gcm, err := newGCM(encodedKey)
	if err != nil {
		return nil, false
	}
	sealed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return nil, false
	}
	opened, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], nil)
	if err != nil || !bytes.HasPrefix(opened, []byte(marker)) {
		return nil, false
	}
	return opened[len(marker):], true
}

func newGCM(encodedKey string) (cipher.AEAD, error) {
	key, err := DecodeKey(encodedKey)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

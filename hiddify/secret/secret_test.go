package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func newTestKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(key)
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := newTestKey(t)
	encrypted, err := Encrypt(key, []byte(`{"SponsorId":"X"}`))
	require.NoError(t, err)
	require.False(t, strings.HasPrefix(encrypted, marker), "the marker must not be visible")
	_, err = base64.StdEncoding.DecodeString(encrypted)
	require.NoError(t, err, "encrypted values are plain base64")

	plaintext, ok := TryDecryptWithKey(key, encrypted)
	require.True(t, ok)
	require.Equal(t, `{"SponsorId":"X"}`, string(plaintext))

	again, err := Encrypt(key, []byte(`{"SponsorId":"X"}`))
	require.NoError(t, err)
	require.NotEqual(t, encrypted, again, "a fresh nonce is used per encryption")
}

func TestTryDecryptTreatsOtherValuesAsNotEncrypted(t *testing.T) {
	key := newTestKey(t)
	encrypted, err := Encrypt(key, []byte("data"))
	require.NoError(t, err)

	for name, value := range map[string]string{
		"plain base64": base64.StdEncoding.EncodeToString([]byte(`{"SponsorId":"X"}`)),
		"not base64":   "not base64!",
		"too short":    "AAAA",
		"no marker":    sealWithoutMarker(t, key, []byte("data")),
		"other key's":  mustEncrypt(t, newTestKey(t), []byte("data")),
		"empty":        "",
	} {
		_, ok := TryDecryptWithKey(key, value)
		require.False(t, ok, name)
	}
	_, ok := TryDecryptWithKey("", encrypted)
	require.False(t, ok, "a build without the key cannot decrypt")

	_, err = Encrypt(base64.StdEncoding.EncodeToString([]byte("short")), []byte("data"))
	require.ErrorContains(t, err, "32 bytes")
}

func mustEncrypt(t *testing.T, key string, plaintext []byte) string {
	t.Helper()
	encrypted, err := Encrypt(key, plaintext)
	require.NoError(t, err)
	return encrypted
}

// a value that decrypts with the right key but lacks the marker is not treated as encrypted
func sealWithoutMarker(t *testing.T, encodedKey string, plaintext []byte) string {
	t.Helper()
	key, err := DecodeKey(encodedKey)
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := make([]byte, gcm.NonceSize())
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, plaintext, nil))
}

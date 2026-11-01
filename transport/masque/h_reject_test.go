package masque

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// Cloudflare's edge refuses a key it has not enrolled with a TLS alert; a network failure or a
// failed check of the server's own key is not a rejection.
func TestH_IsRejected(t *testing.T) {
	require.True(t, IsRejected(fmt.Errorf("failed to dial connect-ip over HTTP/2: %w", errors.New(`connect-ip: failed to send request: Connect "https://cloudflareaccess.com": remote error: tls: unknown certificate`))))
	require.True(t, IsRejected(errors.New("failed to dial connect-ip: CRYPTO_ERROR 0x12e (remote): tls: unknown certificate")))
	require.True(t, IsRejected(fmt.Errorf("connect: %w", &StatusError{Status: http.StatusForbidden, Text: "403 Forbidden"})))
	require.True(t, IsRejected(&StatusError{Status: http.StatusUnauthorized, Text: "401 Unauthorized"}))
	require.False(t, IsRejected(&StatusError{Status: http.StatusBadGateway, Text: "502 Bad Gateway"}))
	require.False(t, IsRejected(errors.New("dial udp 162.159.198.2:443: i/o timeout")))
	require.False(t, IsRejected(errors.New("tls: failed to verify certificate: remote endpoint has a different public key than what we trust in config.json")))
	require.False(t, IsRejected(nil))
}

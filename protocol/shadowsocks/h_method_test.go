package shadowsocks

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// Subscriptions written for Xray clients name ciphers the way Xray does (hiddify/hiddify-app#2622).
func TestH_ShadowsocksXrayMethodNames(t *testing.T) {
	logger := log.NewNOPFactory().NewLogger("test")
	for _, method := range []string{
		"chacha20-poly1305", "aead_chacha20_poly1305", "CHACHA20-POLY1305",
		"xchacha20-poly1305", "aead_xchacha20_poly1305",
		"aead_aes_128_gcm", "aead_aes_256_gcm", "plain",
	} {
		t.Run(method, func(t *testing.T) {
			_, err := NewOutbound(context.Background(), newTestRouter(), logger, "out", option.ShadowsocksOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1},
				Method:        method,
				Password:      "password",
			})
			require.NoError(t, err)
			_, err = NewInbound(context.Background(), newTestRouter(), logger, "in", option.ShadowsocksInboundOptions{
				Method:   method,
				Password: "password",
			})
			require.NoError(t, err)
		})
	}
}

func TestH_ShadowsocksXrayMethodNamesMatchCiphers(t *testing.T) {
	require.Equal(t, "chacha20-ietf-poly1305", normalizeMethod("chacha20-poly1305"))
	require.Equal(t, "xchacha20-ietf-poly1305", normalizeMethod("aead_xchacha20_poly1305"))
	require.Equal(t, "2022-blake3-chacha20-poly1305", normalizeMethod("2022-blake3-chacha20-poly1305"))
	require.Equal(t, "unknown-cipher", normalizeMethod("unknown-cipher"))
}

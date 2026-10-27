package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// A short_id longer than 8 bytes (16 hex digits) is a config error, not a panic in hex.Decode.
func TestH_RealityShortIDTooLong(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	encode := base64.RawURLEncoding.EncodeToString
	for name, shortID := range map[string]string{"9 bytes": "0123456789abcdef01", "odd": "0123456789abcdef0"} {
		t.Run("client "+name, func(t *testing.T) {
			_, err := NewRealityClient(context.Background(), log.NewNOPFactory().Logger(), "example.com", option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: "example.com",
				UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
				Reality:    &option.OutboundRealityOptions{Enabled: true, PublicKey: encode(key.PublicKey().Bytes()), ShortID: shortID},
			})
			require.ErrorContains(t, err, "short_id")
		})
		t.Run("server "+name, func(t *testing.T) {
			_, err := NewRealityServer(context.Background(), log.NewNOPFactory().Logger(), option.InboundTLSOptions{
				Enabled:    true,
				ServerName: "example.com",
				Reality: &option.InboundRealityOptions{
					Enabled:    true,
					Handshake:  option.InboundRealityHandshakeOptions{ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443}},
					PrivateKey: encode(key.Bytes()),
					ShortID:    badoption.Listable[string]{"0123", shortID},
				},
			})
			require.ErrorContains(t, err, "short_id")
		})
	}
	// valid ids still load
	_, err = NewRealityClient(context.Background(), log.NewNOPFactory().Logger(), "example.com", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.com",
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		Reality:    &option.OutboundRealityOptions{Enabled: true, PublicKey: encode(key.PublicKey().Bytes()), ShortID: "0123456789abcdef"},
	})
	require.NoError(t, err)
}

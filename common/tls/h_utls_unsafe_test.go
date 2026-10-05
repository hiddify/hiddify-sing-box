//go:build with_utls

package tls

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// fingerprint "unsafe" (as in Xray) means no uTLS: the standard Go TLS client is used.
func TestH_UTLSUnsafeFingerprintUsesStandardTLS(t *testing.T) {
	for _, fingerprint := range []string{"unsafe", "UNSAFE", " unsafe "} {
		config, err := NewClient(context.Background(), log.NewNOPFactory().Logger(), "example.com", option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: "example.com",
			UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint},
		})
		require.NoError(t, err, fingerprint)
		require.IsType(t, &STDClientConfig{}, config, fingerprint)
	}
}

func TestH_UTLSUnsafeFingerprintRejectedByReality(t *testing.T) {
	_, err := NewClient(context.Background(), log.NewNOPFactory().Logger(), "example.com", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.com",
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "unsafe"},
		Reality:    &option.OutboundRealityOptions{Enabled: true, PublicKey: "yanlaRXp_Qaive33liPQzYJbIsh5rFZmJ8Bd-Iy_wjM"},
	})
	require.ErrorContains(t, err, "fingerprint unsafe is not supported by reality")
}

func TestH_UTLSOptionsUsesUTLS(t *testing.T) {
	var none *option.OutboundUTLSOptions
	require.False(t, none.UsesUTLS())
	require.False(t, (&option.OutboundUTLSOptions{Enabled: false, Fingerprint: "chrome"}).UsesUTLS())
	require.False(t, (&option.OutboundUTLSOptions{Enabled: true, Fingerprint: "unsafe"}).UsesUTLS())
	require.True(t, (&option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}).UsesUTLS())
	require.True(t, (&option.OutboundUTLSOptions{Enabled: true}).UsesUTLS(), "empty fingerprint is chrome")
}

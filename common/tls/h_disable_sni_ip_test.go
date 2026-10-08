package tls

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// disable_sni with an IP server name changes nothing (an IP is never sent as SNI), so the standard
// verification stays: QUIC parrots cannot run a VerifyConnection hook.
func TestH_DisableSNIWithIPServerName(t *testing.T) {
	logger := log.NewNOPFactory().NewLogger("tls")
	config, err := NewSTDClient(context.Background(), logger, "", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "203.0.113.7",
		DisableSNI: true,
	})
	require.NoError(t, err)
	std, err := config.STDConfig()
	require.NoError(t, err)
	require.Equal(t, "203.0.113.7", std.ServerName)
	require.False(t, std.InsecureSkipVerify)
	require.Nil(t, std.VerifyConnection)

	// with a domain, disable_sni still hides it and verifies the name itself
	config, err = NewSTDClient(context.Background(), logger, "", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.com",
		DisableSNI: true,
	})
	require.NoError(t, err)
	std, err = config.STDConfig()
	require.NoError(t, err)
	require.Empty(t, std.ServerName)
	require.NotNil(t, std.VerifyConnection)
}

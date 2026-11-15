package xhttp

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// Over REALITY the client speaks HTTP/2, as Xray's does, and so keeps its connections for the next
// proxy connection. It spoke HTTP/1.1, without keep-alive, and every proxy connection made a REALITY
// handshake of its own.
func TestH_RealitySpeaksHTTP2(t *testing.T) {
	config, err := tls.NewClient(context.Background(), logger.NOP(), "example.com", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.com",
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: "8b46o5kOSkq4BbpJFxm3zgU1T9gkv9zl4qRHSv8GLFQ",
			ShortID:   "0123456789abcdef",
		},
	})
	require.NoError(t, err)
	require.True(t, tls.IsReality(config))
	require.Equal(t, "2", decideHTTPVersion(hDefaultALPN(config)))
}

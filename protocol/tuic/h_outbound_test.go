package tuic

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func hTUICOptions(mode string) option.TUICOutboundOptions {
	return option.TUICOutboundOptions{
		ServerOptions:               option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		UUID:                        "b831381d-6324-4d53-ad4f-8cda48b30811",
		UDPRelayMode:                mode,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true, ServerName: "example.com"}},
	}
}

// A misspelt udp_relay_mode is rejected instead of silently meaning native.
func TestH_TUICUDPRelayMode(t *testing.T) {
	for _, mode := range []string{"", "native", "quic"} {
		_, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "tuic", hTUICOptions(mode))
		require.NoError(t, err, mode)
	}
	for _, mode := range []string{"quick", "Native", "stream"} {
		_, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "tuic", hTUICOptions(mode))
		require.ErrorContains(t, err, "udp_relay_mode", mode)
	}
}

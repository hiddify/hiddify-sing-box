package vless

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// A dial that fails after the connection to the server was made closes it, whatever fails: the
// failures after the handshakes each had to close it, and these did not.
func TestH_VLESSFailureAfterConnectClosesConn(t *testing.T) {
	packetAddr := "packetaddr"
	for name, dial := range map[string]func(ctx context.Context, outbound *Outbound) error{
		"unknown network": func(ctx context.Context, outbound *Outbound) error {
			_, err := outbound.DialContext(ctx, "sctp", M.ParseSocksaddr("example.com:443"))
			return err
		},
		"packetaddr to a domain": func(ctx context.Context, outbound *Outbound) error {
			_, err := outbound.DialContext(ctx, N.NetworkUDP, M.ParseSocksaddr("example.com:443"))
			return err
		},
		"packetaddr to a domain, listen packet": func(ctx context.Context, outbound *Outbound) error {
			_, err := outbound.ListenPacket(ctx, M.ParseSocksaddr("example.com:443"))
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			port, closedByClient := hBadServer(t)
			created, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "vless", option.VLESSOutboundOptions{
				ServerOptions:  option.ServerOptions{Server: "127.0.0.1", ServerPort: port},
				UUID:           "b831381d-6324-4d53-ad4f-8cda48b30811",
				PacketEncoding: &packetAddr,
			})
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.Error(t, dial(ctx, created.(*Outbound)))
			require.True(t, <-closedByClient, "the connection to the server leaked")
		})
	}
}

// Vision works on a TLS, REALITY or VLESS encryption layer. Without one the config is refused:
// it loaded, and every dial connected to the server, failed, and left the connection open.
func TestH_VLESSVisionNeedsALayer(t *testing.T) {
	options := option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		UUID:          "b831381d-6324-4d53-ad4f-8cda48b30811",
		Flow:          "xtls-rprx-vision",
	}
	_, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "vless", options)
	require.ErrorContains(t, err, "needs TLS, REALITY or VLESS encryption")

	options.TLS = &option.OutboundTLSOptions{Enabled: true, ServerName: "example.com"}
	_, err = NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "vless", options)
	require.NoError(t, err)

	_, clientX25519, _, _ := generateKeyStrings(t)
	options.TLS = nil
	options.Encryption = "mlkem768x25519plus.native.1rtt." + clientX25519
	_, err = NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "vless", options)
	require.NoError(t, err)
}

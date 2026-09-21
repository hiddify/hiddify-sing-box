package v2rayraw

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

// Client implements a "raw" V2Ray transport: it dials the underlying
// connection (optionally wrapped in TLS) and passes it through unmodified,
// without any additional framing or headers, similar to Xray's "raw" stream
// setting.
type Client struct {
	dialer     N.Dialer
	serverAddr M.Socksaddr
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayRawOptions, tlsConfig tls.Config) (*Client, error) {
	if tlsConfig != nil {
		dialer = tls.NewDialer(dialer, tlsConfig)
	}
	return &Client{
		dialer:     dialer,
		serverAddr: serverAddr,
	}, nil
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	return c.dialer.DialContext(ctx, N.NetworkTCP, c.serverAddr)
}

func (c *Client) Close() error {
	return nil
}

//go:build with_kcp

package v2raykcp

import (
	"context"
	"io"
	"math/rand/v2"
	"net"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/sagernet/sing-box/transport/v2raykcp/kcp"
	"github.com/xtls/xray-core/common/buf"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

// conversation numbers the client's sessions, starting at random as Xray does
var conversation = rand.Uint32()

type Client struct {
	dialer     N.Dialer
	serverAddr M.Socksaddr
	config     *kcp.Config
	tlsConfig  tls.Config
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayKCPOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	config, err := newConfig(options)
	if err != nil {
		return nil, err
	}
	return &Client{dialer: dialer, serverAddr: serverAddr, config: config, tlsConfig: tlsConfig}, nil
}

// DialContext opens a UDP socket to the server (finalmask UDP masks of the dialer apply to it)
// and runs one mKCP session over it.
func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	packetConn, err := c.dialer.DialContext(ctx, N.NetworkUDP, c.serverAddr)
	if err != nil {
		return nil, err
	}
	session := kcp.NewConnection(kcp.ConnMetadata{
		LocalAddr:    packetConn.LocalAddr(),
		RemoteAddr:   packetConn.RemoteAddr(),
		Conversation: uint16(atomic.AddUint32(&conversation, 1)),
	}, packetConn, packetConn, c.config)
	go readSegments(packetConn, session)
	var conn net.Conn = session
	if c.tlsConfig != nil {
		conn, err = tls.ClientHandshake(ctx, conn, c.tlsConfig)
		if err != nil {
			session.Close()
			return nil, err
		}
	}
	return conn, nil
}

// readSegments feeds the session with the segments read from the socket until it closes.
func readSegments(input io.Reader, session *kcp.Connection) {
	reader := &kcp.KCPPacketReader{}
	for {
		payload := buf.New()
		if _, err := payload.ReadFrom(input); err != nil {
			payload.Release()
			session.Close() // the socket is gone; Terminate would free buffers under a running Read
			return
		}
		segments := reader.Read(payload.Bytes())
		payload.Release()
		if len(segments) > 0 {
			session.Input(segments)
		}
	}
}

func (c *Client) Close() error {
	return nil
}

package v2rayxdrive

import (
	"context"
	"net"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/hiddify/finalmask"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/xdrive"
)

func init() {
	v2ray.RegisterXDriveConstructor(NewServer, NewClient)
}

const protocolName = "xdrive"

// streamSettings is the Xray stream of XDRIVE; every socket it opens to the storage service goes
// through dialer.
func streamSettings(options option.V2RayXDriveOptions, tlsConfig tls.Config, serverAddr M.Socksaddr, dialer N.Dialer) (*internet.MemoryStreamConfig, error) {
	securitySettings := xrayTLSConfig(tlsConfig, serverAddr)
	config, err := buildConfig(options, slices.Equal(securitySettings.NextProtocol, []string{"h3"}))
	if err != nil {
		return nil, err
	}
	return &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: config,
		SecurityType:     "tls",
		SecuritySettings: securitySettings,
		Destination:      frontingDestination(options),
		FinalMask:        (*finalmask.Masks)(nil).XrayFinalMask(dialer.DialContext, dialer.ListenPacket),
	}, nil
}

var _ adapter.V2RayClientTransport = (*Client)(nil)

// Client opens one XDRIVE session per connection. Xray's XDRIVE expects VLESS with Mux.Cool on
// top, so that a session carries many connections.
type Client struct {
	streamSettings *internet.MemoryStreamConfig
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayXDriveOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	settings, err := streamSettings(options, tlsConfig, serverAddr, dialer)
	if err != nil {
		return nil, err
	}
	return &Client{streamSettings: settings}, nil
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	// the session has no address: the server finds it in the storage
	return xdrive.Dial(ctx, xnet.Destination{Network: xnet.Network_TCP, Address: xnet.AnyIP}, c.streamSettings)
}

func (c *Client) Close() error {
	return nil
}

var _ adapter.V2RayServerTransport = (*Server)(nil)

// Server accepts the sessions that clients announce in the storage. It listens on no socket: the
// inbound's TCP listener is closed as soon as it is handed over.
type Server struct {
	ctx            context.Context
	logger         logger.ContextLogger
	handler        adapter.V2RayServerTransportHandler
	streamSettings *internet.MemoryStreamConfig

	access   sync.Mutex
	listener internet.Listener
	done     chan struct{}
	closed   bool
}

func NewServer(ctx context.Context, logger logger.ContextLogger, options option.V2RayXDriveOptions, tlsConfig tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (adapter.V2RayServerTransport, error) {
	// the server is a client of the storage service too; its requests go out the default outbound
	outbound := dialer.NewDefaultOutbound(ctx)
	settings, err := streamSettings(options, nil, M.Socksaddr{}, outbound)
	if err != nil {
		return nil, err
	}
	return &Server{
		ctx:            ctx,
		logger:         logger,
		handler:        handler,
		streamSettings: settings,
		done:           make(chan struct{}),
	}, nil
}

func (s *Server) Network() []string {
	return []string{N.NetworkTCP}
}

func (s *Server) Serve(listener net.Listener) error {
	listener.Close()
	s.access.Lock()
	if s.closed {
		s.access.Unlock()
		return net.ErrClosed
	}
	xlistener, err := xdrive.Serve(s.ctx, xnet.AnyIP, 0, s.streamSettings, s.newConnection)
	if err != nil {
		s.access.Unlock()
		return err
	}
	s.listener = xlistener
	s.access.Unlock()
	<-s.done
	return net.ErrClosed
}

func (s *Server) newConnection(conn stat.Connection) {
	s.handler.NewConnectionEx(s.ctx, conn, M.Socksaddr{}, M.Socksaddr{}, nil)
}

func (s *Server) ServePacket(listener net.PacketConn) error {
	return nil
}

func (s *Server) Close() error {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.done)
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

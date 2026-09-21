package v2rayraw

import (
	"context"
	"net"
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

var _ adapter.V2RayServerTransport = (*Server)(nil)

// Server implements a "raw" V2Ray transport: it accepts the (optionally
// TLS-wrapped) connection and hands it directly to the handler without any
// additional framing or headers, similar to Xray's "raw" stream setting.
type Server struct {
	ctx       context.Context
	tlsConfig tls.ServerConfig
	handler   adapter.V2RayServerTransportHandler
}

func NewServer(ctx context.Context, logger log.ContextLogger, options option.V2RayRawOptions, tlsConfig tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (*Server, error) {
	return &Server{
		ctx:       ctx,
		tlsConfig: tlsConfig,
		handler:   handler,
	}, nil
}

func (s *Server) Network() []string {
	return []string{N.NetworkTCP}
}

func (s *Server) Serve(listener net.Listener) error {
	if s.tlsConfig != nil {
		listener = aTLS.NewListener(listener, s.tlsConfig)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			if E.IsClosedOrCanceled(err) {
				return nil
			}
			return err
		}
		go s.handler.NewConnectionEx(log.ContextWithNewID(s.ctx), conn, M.SocksaddrFromNet(conn.RemoteAddr()), M.Socksaddr{}, nil)
	}
}

func (s *Server) ServePacket(listener net.PacketConn) error {
	return os.ErrInvalid
}

func (s *Server) Close() error {
	return nil
}

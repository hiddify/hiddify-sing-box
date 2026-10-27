//go:build with_kcp

package v2raykcp

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/sagernet/sing-box/transport/v2raykcp/kcp"
)

var _ adapter.V2RayServerTransport = (*Server)(nil)

type sessionID struct {
	source       netip.AddrPort
	conversation uint16
}

// Server runs mKCP sessions over the inbound's UDP socket, one per sender and conversation, as
// Xray's mKCP listener does.
type Server struct {
	ctx       context.Context
	logger    logger.ContextLogger
	config    *kcp.Config
	tlsConfig tls.ServerConfig
	handler   adapter.V2RayServerTransportHandler

	access   sync.Mutex
	listener net.PacketConn
	sessions map[sessionID]*kcp.Connection
}

func NewServer(ctx context.Context, logger logger.ContextLogger, options option.V2RayKCPOptions, tlsConfig tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (adapter.V2RayServerTransport, error) {
	config, err := newConfig(options)
	if err != nil {
		return nil, err
	}
	return &Server{
		ctx:       ctx,
		logger:    logger,
		config:    config,
		tlsConfig: tlsConfig,
		handler:   handler,
		sessions:  make(map[sessionID]*kcp.Connection),
	}, nil
}

func (s *Server) Network() []string {
	return []string{N.NetworkUDP}
}

func (s *Server) Serve(listener net.Listener) error {
	return os.ErrInvalid
}

func (s *Server) ServePacket(listener net.PacketConn) error {
	s.access.Lock()
	s.listener = listener
	s.access.Unlock()
	go s.readLoop(listener)
	return nil
}

func (s *Server) readLoop(listener net.PacketConn) {
	reader := &kcp.KCPPacketReader{}
	buffer := make([]byte, 65535)
	for {
		n, addr, err := listener.ReadFrom(buffer)
		if err != nil {
			if !E.IsClosedOrCanceled(err) {
				s.logger.ErrorContext(s.ctx, E.Cause(err, "read mKCP packet"))
			}
			return
		}
		segments := reader.Read(buffer[:n])
		if len(segments) == 0 {
			continue
		}
		source := M.SocksaddrFromNet(addr).Unwrap().AddrPort()
		id := sessionID{source: source, conversation: segments[0].Conversation()}
		s.access.Lock()
		session, found := s.sessions[id]
		if !found {
			if segments[0].Command() == kcp.CommandTerminate {
				s.access.Unlock()
				continue
			}
			writer := &sessionWriter{server: s, id: id, listener: listener, destination: addr}
			session = kcp.NewConnection(kcp.ConnMetadata{
				LocalAddr:    listener.LocalAddr(),
				RemoteAddr:   addr,
				Conversation: id.conversation,
			}, writer, writer, s.config)
			s.sessions[id] = session
			go s.handle(session, source)
		}
		s.access.Unlock()
		session.Input(segments)
	}
}

func (s *Server) handle(session *kcp.Connection, source netip.AddrPort) {
	ctx := log.ContextWithNewID(s.ctx)
	var conn net.Conn = session
	if s.tlsConfig != nil {
		tlsConn, err := tls.ServerHandshake(ctx, session, s.tlsConfig)
		if err != nil {
			s.logger.ErrorContext(ctx, E.Cause(err, "mKCP TLS handshake"))
			session.Close()
			return
		}
		conn = tlsConn
	}
	s.handler.NewConnectionEx(ctx, conn, M.SocksaddrFromNetIP(source), M.Socksaddr{}, nil)
}

func (s *Server) remove(id sessionID) {
	s.access.Lock()
	delete(s.sessions, id)
	s.access.Unlock()
}

func (s *Server) Close() error {
	s.access.Lock()
	listener := s.listener
	sessions := make([]*kcp.Connection, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	s.access.Unlock()
	for _, session := range sessions {
		go session.Close() // Terminate frees buffers under a running Read
	}
	if listener != nil {
		return listener.Close()
	}
	return nil
}

// sessionWriter sends a session's segments to its client and drops the session when it closes.
type sessionWriter struct {
	server      *Server
	id          sessionID
	listener    net.PacketConn
	destination net.Addr
}

func (w *sessionWriter) Write(payload []byte) (int, error) {
	return w.listener.WriteTo(payload, w.destination)
}

func (w *sessionWriter) Close() error {
	w.server.remove(w.id)
	return nil
}

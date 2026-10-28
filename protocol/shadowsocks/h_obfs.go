package shadowsocks

import (
	"context"
	"net"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	obfs "github.com/sagernet/sing-box/transport/simple-obfs"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// obfsRecordLimit bounds what is kept for replay. A Shadowsocks header and the
// obfs request around it are far smaller; a client that sends more without
// authenticating is just closed.
const obfsRecordLimit = 16 << 10

// obfsServer runs the server side of simple-obfs in front of a Shadowsocks service.
// Like obfs-server --failover, a connection that is not simple-obfs is passed to the
// fallback address, so a probe sees the decoy site instead of a closed connection.
// Unlike it, so is a connection that passes obfs but fails Shadowsocks authentication
// (unknown user, wrong password, replayed salt): a probe that copies the obfs request
// gets the decoy as well.
type obfsServer struct {
	mode     string
	hosts    []string
	fallback M.Socksaddr
}

func newObfsServer(options option.ShadowsocksInboundOptions) (obfsServer, error) {
	switch options.ObfsMode {
	case "", "http", "tls":
	default:
		return obfsServer{}, E.New("shadowsocks: unsupported obfs mode: ", options.ObfsMode)
	}
	server := obfsServer{mode: options.ObfsMode}
	for _, host := range strings.Split(options.ObfsHost, ",") {
		if host = strings.TrimSpace(host); host != "" {
			server.hosts = append(server.hosts, host)
		}
	}
	if len(server.hosts) > 0 && options.ObfsMode == "" {
		return obfsServer{}, E.New("shadowsocks: obfs_host requires obfs_mode")
	}
	if options.ObfsFallback != nil && options.ObfsFallback.Server != "" {
		if options.ObfsMode == "" {
			return obfsServer{}, E.New("shadowsocks: obfs_fallback requires obfs_mode")
		}
		server.fallback = options.ObfsFallback.Build()
		if !server.fallback.IsValid() || server.fallback.Port == 0 {
			return obfsServer{}, E.New("shadowsocks: invalid obfs_fallback address: ", server.fallback)
		}
	}
	return server, nil
}

// serve runs the obfs handshake and then service, which is the Shadowsocks service
// handling the unwrapped connection. If anything fails before Shadowsocks has
// authenticated the client, the bytes the client sent are replayed to the fallback.
func (s obfsServer) serve(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc, inbound adapter.Inbound, router adapter.ConnectionRouterEx, logger logger.ContextLogger, service func(ctx context.Context, conn net.Conn) error) {
	raw := conn
	var recorder *obfsRecorder
	if s.fallback.IsValid() {
		recorder = &obfsRecorder{Conn: conn}
		conn = recorder
		ctx = context.WithValue(ctx, obfsRecorderKey{}, recorder)
	}
	var err error
	if s.mode != "" {
		var obfsConn net.Conn
		obfsConn, _, err = obfs.ServerHandshake(conn, s.mode, s.hosts...)
		if err == nil {
			conn = obfsConn
		}
	}
	if err == nil {
		err = service(ctx, conn)
	}
	if err != nil && recorder != nil {
		if replay, ok := recorder.unauthenticated(); ok {
			metadata.Inbound = inbound.Tag()
			metadata.InboundType = inbound.Type()
			metadata.Destination = s.fallback
			logger.InfoContext(ctx, "fallback connection from ", metadata.Source, " to ", s.fallback, ": ", err)
			router.RouteConnectionEx(ctx, bufio.NewCachedConn(raw, buf.As(replay)), metadata, onClose)
			return
		}
	}
	N.CloseOnHandshakeFailure(conn, onClose, err)
	if err != nil {
		if E.IsClosedOrCanceled(err) {
			logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
		}
	}
}

type obfsRecorderKey struct{}

// markAuthenticated is called by the inbounds' connection handlers, which the
// Shadowsocks service only reaches once the client has authenticated. From then on
// nothing is recorded, and a later failure closes the connection instead of replaying it.
func markAuthenticated(ctx context.Context) {
	if recorder, loaded := ctx.Value(obfsRecorderKey{}).(*obfsRecorder); loaded {
		recorder.authenticate()
	}
}

// obfsRecorder keeps what the client sent until it authenticates.
type obfsRecorder struct {
	net.Conn
	access        sync.Mutex
	recorded      []byte
	authenticated bool
	overflow      bool
}

func (r *obfsRecorder) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	if n > 0 {
		r.access.Lock()
		if !r.authenticated && !r.overflow {
			if len(r.recorded)+n > obfsRecordLimit {
				r.overflow = true
				r.recorded = nil
			} else {
				r.recorded = append(r.recorded, b[:n]...)
			}
		}
		r.access.Unlock()
	}
	return n, err
}

func (r *obfsRecorder) authenticate() {
	r.access.Lock()
	r.authenticated = true
	r.recorded = nil
	r.access.Unlock()
}

// unauthenticated returns what the client sent, if it never authenticated and
// there is something to replay.
func (r *obfsRecorder) unauthenticated() ([]byte, bool) {
	r.access.Lock()
	defer r.access.Unlock()
	if r.authenticated || r.overflow || len(r.recorded) == 0 {
		return nil, false
	}
	return r.recorded, true
}

func (r *obfsRecorder) Upstream() any {
	return r.Conn
}

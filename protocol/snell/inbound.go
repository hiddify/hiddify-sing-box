package snellprotocol

import (
	"context"
	"net"
	"sync"

	snell "github.com/reF1nd/sing-snell"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	obfs "github.com/sagernet/sing-box/transport/simple-obfs"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	udpnat "github.com/sagernet/sing/common/udpnat2"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.SnellInboundOptions](registry, C.TypeSnell, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx      context.Context
	router   adapter.ConnectionRouterEx
	logger   logger.ContextLogger
	listener *listener.Listener
	service  *snell.Service
	obfsMode string
	obfsHost string
	// v5 QUIC proxy state
	psk          []byte
	userPSKs     [][]byte // non-nil in multi-user mode; used for QUIC proxy auth
	version      int
	udpNat       *udpnat.Service
	quicSessions sync.Map // key: netip.AddrPort → *snell.QUICProxySession
	// multi-user state
	users []option.SnellUser
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SnellInboundOptions) (adapter.Inbound, error) {
	if options.PSK == "" && len(options.Users) == 0 {
		return nil, E.New("snell: psk or users is required")
	}
	if options.PSK != "" && len(options.Users) > 0 {
		return nil, E.New("snell: psk and users are mutually exclusive")
	}

	switch options.ObfsMode {
	case "", "http":
	case "tls":
		ver := options.Version
		if ver == 0 {
			ver = snell.DefaultVersion
		}
		if ver >= snell.Version4 {
			return nil, E.New("snell: obfs_mode TLS is insecure and not supported for v4/v5; use ShadowTLS instead")
		}
	default:
		return nil, E.New("snell: unsupported obfs mode: ", options.ObfsMode)
	}

	i := &Inbound{
		Adapter:  inbound.NewAdapter(C.TypeSnell, tag),
		ctx:      ctx,
		router:   uot.NewRouter(router, logger),
		logger:   logger,
		obfsMode: options.ObfsMode,
		obfsHost: options.ObfsHost,
		psk:      []byte(options.PSK),
		version:  options.Version,
		users:    options.Users,
	}

	networks := []string{N.NetworkTCP}
	if options.Version >= snell.Version5 {
		networks = append(networks, N.NetworkUDP)
		i.udpNat = udpnat.New((*inboundUDPHandler)(i), i.preparePacketConnection, snell.QUICProxySessionIdleTimeout, false)
	}
	var serviceConfig snell.ServiceConfig
	if len(options.Users) > 0 {
		users := make([]snell.User, len(options.Users))
		userPSKs := make([][]byte, len(options.Users))
		for j, u := range options.Users {
			users[j] = snell.User{Name: u.Name, PSK: []byte(u.PSK)}
			userPSKs[j] = []byte(u.PSK)
		}
		i.userPSKs = userPSKs
		serviceConfig = snell.ServiceConfig{
			Users:      users,
			Version:    options.Version,
			UDPEnabled: true,
			Handler:    (*inboundHandler)(i),
			UDPHandler: (*inboundUDPHandler)(i),
			Logger:     logger,
		}
	} else {
		serviceConfig = snell.ServiceConfig{
			PSK:        []byte(options.PSK),
			Version:    options.Version,
			UDPEnabled: true,
			Handler:    (*inboundHandler)(i),
			UDPHandler: (*inboundUDPHandler)(i),
			Logger:     logger,
		}
	}
	service, err := snell.NewService(serviceConfig)
	if err != nil {
		return nil, err
	}
	i.service = service

	i.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           networks,
		Listen:            options.ListenOptions,
		ConnectionHandler: i,
		PacketHandler:     (*inboundPacketHandler)(i),
	})
	return i, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return h.listener.Start()
}

func (h *Inbound) Close() error {
	return h.listener.Close()
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	switch h.obfsMode {
	case "http":
		conn = obfs.NewHTTPObfsServer(conn)
	case "tls":
		conn = obfs.NewTLSObfsServer(conn)
	}
	err := h.service.NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
	}
}

type inboundHandler Inbound

func (h *inboundHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.Source = source
	metadata.Destination = destination.Unwrap()
	if userIdx, loaded := auth.UserFromContext[int](ctx); loaded && userIdx < len(h.users) {
		metadata.User = h.users[userIdx].Name
	}
	h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

type inboundUDPHandler Inbound

func (h *inboundUDPHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.Source = source
	metadata.Destination = destination.Unwrap()
	if userIdx, loaded := auth.UserFromContext[int](ctx); loaded && userIdx < len(h.users) {
		metadata.User = h.users[userIdx].Name
	}
	h.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

// preparePacketConnection is the udpnat PrepareFunc for QUIC proxy sessions.
// It returns a PacketWriter that sends raw UDP responses back to the client.
// In multi-user mode, userData is *snell.QUICProxySession and carries the
// matched UserIndex which is injected into the context for auth_user routing.
func (h *Inbound) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	ctx := log.ContextWithNewID(h.ctx)
	if qsess, ok := userData.(*snell.QUICProxySession); ok && qsess != nil && qsess.UserIndex >= 0 {
		ctx = auth.ContextWithUser(ctx, qsess.UserIndex)
	}
	return true, ctx, &quicProxyResponseWriter{
			writer:     h.listener.PacketWriter(),
			clientAddr: source,
		}, func(err error) {
			h.quicSessions.Delete(source.AddrPort())
		}
}

// quicProxyResponseWriter rewrites the destination to the original client
// address so that responses from the outbound go back to the right client.
type quicProxyResponseWriter struct {
	writer     N.PacketWriter
	clientAddr M.Socksaddr
}

func (w *quicProxyResponseWriter) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	return w.writer.WritePacket(buffer, w.clientAddr)
}

// inboundPacketHandler handles raw UDP datagrams from the listener for
// Snell v5 QUIC proxy mode. It decrypts the Snell framing to recover the
// original UDP payload and target, then feeds it into udpnat so that
// routing rules, domain sniffing and detour all apply normally.
type inboundPacketHandler Inbound

func (h *inboundPacketHandler) NewPacket(buffer *buf.Buffer, source M.Socksaddr) {
	defer buffer.Release()
	if h.udpNat == nil {
		return
	}
	data := buffer.Bytes()
	if len(data) == 0 {
		return
	}

	val, hasSession := h.quicSessions.Load(source.AddrPort())
	if hasSession {
		qsess := val.(*snell.QUICProxySession)
		qsess.Touch()

		var payload []byte
		if snell.IsQUICLooking(data[0]) {
			// Raw QUIC short-header — forward as-is
			payload = data
		} else {
			// Duplicate init frame — decrypt to recover raw UDP payload
			var err error
			payload, err = qsess.DecodeDuplicateInit(data)
			if err != nil {
				h.logger.Error("quic proxy: decode duplicate init: ", err)
				return
			}
		}
		if len(payload) > 0 {
			// Pass qsess as userData so that if the udpnat entry was evicted
			// (timeout race between the two maps), PrepareFunc correctly
			// re-injects the user context on re-creation.
			h.udpNat.NewPacket([][]byte{payload}, source, qsess.Target(), qsess)
		}
		return
	}

	// No existing session
	if snell.IsQUICLooking(data[0]) {
		// QUIC-looking without a session context — discard
		h.logger.Debug("quic proxy: discarding QUIC-looking packet without session from ", source)
		return
	}

	// Parse Snell QUIC proxy init frame.  In multi-user mode try every PSK;
	// in single-user mode use h.psk directly.
	var qsess *snell.QUICProxySession
	var firstPayload []byte
	if len(h.userPSKs) > 0 {
		var err error
		qsess, firstPayload, err = snell.ParseQUICProxyInitMulti(h.userPSKs, data)
		if err != nil {
			h.logger.Error("quic proxy: parse init from ", source, ": ", err)
			return
		}
	} else {
		var err error
		qsess, firstPayload, err = snell.ParseQUICProxyInit(h.psk, data)
		if err != nil {
			h.logger.Error("quic proxy: parse init from ", source, ": ", err)
			return
		}
	}

	// LoadOrStore so that if two concurrent goroutines both parse an init
	// frame from the same source (very rare: same client port, same instant),
	// only one session wins and both payloads are queued under the same
	// crypto/user context.  This avoids a benign but unnecessary duplicate
	// firstPayload delivery that a plain Store+NewPacket would cause.
	if actual, loaded := h.quicSessions.LoadOrStore(source.AddrPort(), qsess); loaded {
		qsess = actual.(*snell.QUICProxySession)
	}

	target := qsess.Target()
	h.logger.Info("quic proxy: new session from ", source, " to ", target)

	if len(firstPayload) > 0 {
		// Pass qsess as userData so preparePacketConnection can inject the
		// matched user index into the context for auth_user rule matching.
		h.udpNat.NewPacket([][]byte{firstPayload}, source, target, qsess)
	}
}

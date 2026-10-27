package call

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/call"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/bufio/deadline"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.CallInboundOptions](registry, C.TypeCall, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx     context.Context
	router  adapter.ConnectionRouterEx
	logger  logger.ContextLogger
	options option.CallInboundOptions
	dialer  N.Dialer
	bridge  atomic.Pointer[call.Bridge] // set by the connect loop, read on close
	cancel  context.CancelFunc          // stops the connect retries on close
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.CallInboundOptions) (adapter.Inbound, error) {
	if options.Platform == "" {
		return nil, E.New("missing platform")
	}
	if err := call.CheckMode(options.Platform, options.Mode); err != nil { // at load: the connect is retried forever
		return nil, err
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, true)
	if err != nil {
		return nil, err
	}
	return &Inbound{
		Adapter: inbound.NewAdapter(C.TypeCall, tag),
		ctx:     ctx,
		router:  router,
		logger:  logger,
		options: options,
		dialer:  outboundDialer,
	}, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	ctx, cancel := context.WithCancel(h.ctx)
	h.cancel = cancel
	scope.Add(func() error {
		h.cancel()
		if bridge := h.bridge.Load(); bridge != nil {
			return bridge.Close()
		}
		return nil
	})
	go h.run(ctx)
	return nil
}

func (h *Inbound) run(ctx context.Context) {
	dnsRouter := service.FromContext[adapter.DNSRouter](h.ctx)
	connectWithRetry(ctx, h.logger, func() (*call.Bridge, error) {
		return h.connect(ctx, dnsRouter)
	}, h.bridge.Store, nil)
}

func (h *Inbound) connect(ctx context.Context, dnsRouter adapter.DNSRouter) (*call.Bridge, error) {
	bridge, err := call.Connect(ctx, call.Config{
		Platform:     h.options.Platform,
		Mode:         h.options.Mode,
		JoinLink:     h.options.JoinLink,
		CookieString: h.options.Cookies.Header(),
		Email:        h.options.Email,
		Password:     h.options.Password,
		ReadBuffer:   h.options.ReadBuffer,
		Role:         call.RoleCreator,
		Dialer:       h.dialer,
		DNSRouter:    dnsRouter,
		Logger:       h.logger,
	})
	if err != nil {
		return nil, err
	}
	bridge.SetAcceptHandler(func(conn net.Conn, destination string) {
		h.handleConnection(conn, M.ParseSocksaddr(destination))
	})
	bridge.SetUDPAcceptHandler(func(conn net.Conn, destination string) {
		h.handlePacketConnection(bufio.NewUnbindPacketConnWithAddr(conn, M.ParseSocksaddr(destination)), M.ParseSocksaddr(destination))
	})
	return bridge, nil
}

func (h *Inbound) handleConnection(conn net.Conn, destination M.Socksaddr) {
	ctx := log.ContextWithNewID(h.ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.Source = M.Socksaddr{}
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "inbound connection to ", destination)
	h.router.RouteConnectionEx(ctx, deadline.NewConn(conn), metadata, N.OnceClose(func(it error) {
		conn.Close()
	}))
}

func (h *Inbound) handlePacketConnection(conn N.PacketConn, destination M.Socksaddr) {
	ctx := log.ContextWithNewID(h.ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.Source = M.Socksaddr{}
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "inbound packet connection to ", destination)
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, N.OnceClose(func(it error) {
		conn.Close()
	}))
}

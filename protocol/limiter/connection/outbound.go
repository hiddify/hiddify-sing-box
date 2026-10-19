package connection

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/onclose"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.ConnectionLimiterOutboundOptions](registry, C.TypeConnectionLimiter, NewOutbound)
}

var _ adapter.Lifecycle = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	ctx         context.Context
	outbound    adapter.OutboundManager
	connection  adapter.ConnectionManager
	logger      logger.ContextLogger
	strategy    ConnectionStrategy
	outboundTag string
	detour      adapter.Outbound
	router      *route.Router
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ConnectionLimiterOutboundOptions) (adapter.Outbound, error) {
	if options.Strategy == "" {
		return nil, E.New("missing strategy")
	}
	if options.Route.Final == "" {
		return nil, E.New("missing final outbound")
	}
	var strategy ConnectionStrategy
	var err error
	switch options.Strategy {
	case "users":
		usersStrategies := make(map[string]ConnectionStrategy, len(options.Users))
		for _, user := range options.Users {
			userStrategy, err := CreateStrategy(user.Strategy, user.ConnectionType, NewDefaultLock(user.Count))
			if err != nil {
				return nil, err
			}
			usersStrategies[user.Name] = userStrategy
		}
		strategy = NewUsersConnectionStrategy(usersStrategies)
	case "manager":
		strategy = NewManagerConnectionStrategy()
	default:
		strategy, err = CreateStrategy(options.Strategy, options.ConnectionType, NewDefaultLock(options.Count))
		if err != nil {
			return nil, err
		}
	}
	logFactory := service.FromContext[log.Factory](ctx)
	r := route.NewRouter(ctx, logFactory, F.ToString("router/", C.TypeConnectionLimiter, "[", tag, "]"), options.Route, option.DNSOptions{})
	err = r.Initialize(options.Route.Rules, options.Route.RuleSet)
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter:     outbound.NewAdapter(C.TypeConnectionLimiter, tag, nil, []string{}),
		ctx:         ctx,
		outbound:    service.FromContext[adapter.OutboundManager](ctx),
		connection:  service.FromContext[adapter.ConnectionManager](ctx),
		logger:      logger,
		outboundTag: options.Route.Final,
		strategy:    strategy,
		router:      r,
	}
	return outbound, nil
}

func (h *Outbound) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateStart {
		detour, loaded := h.outbound.Outbound(h.outboundTag)
		if !loaded {
			return E.New("outbound not found: ", h.outboundTag)
		}
		h.detour = detour
	}
	return h.router.Start(stage, scope)
}

func (h *Outbound) References() []string {
	return h.router.References()
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	onClose, lockCtx, err := h.strategy.request(ctx, adapter.ContextFrom(ctx))
	if err != nil {
		return nil, err
	}
	conn, err := h.detour.DialContext(ctx, network, destination)
	if err != nil {
		onClose()
		return nil, err
	}
	conn = onclose.NewConn(conn, onClose)
	if lockCtx != nil {
		go connChecker(lockCtx, conn.Close)
	}
	return conn, nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	onClose, lockCtx, err := h.strategy.request(ctx, adapter.ContextFrom(ctx))
	if err != nil {
		return nil, err
	}
	conn, err := h.detour.ListenPacket(ctx, destination)
	if err != nil {
		onClose()
		return nil, err
	}
	conn = onclose.NewPacketConn(conn, onClose)
	if lockCtx != nil {
		go connChecker(lockCtx, conn.Close)
	}
	return conn, nil
}

func (h *Outbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	limiterOnClose, lockCtx, err := h.strategy.request(ctx, &metadata)
	if err != nil {
		h.logger.ErrorContext(ctx, err)
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	conn = onclose.NewConn(conn, limiterOnClose)
	if lockCtx != nil {
		go connChecker(lockCtx, conn.Close)
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
	return
}

func (h *Outbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	limiterOnClose, lockCtx, err := h.strategy.request(ctx, &metadata)
	if err != nil {
		h.logger.ErrorContext(ctx, err)
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	conn = bufio.NewPacketConn(onclose.NewPacketConn(bufio.NewNetPacketConn(conn), limiterOnClose))
	if lockCtx != nil {
		go connChecker(lockCtx, conn.Close)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
	return
}

func (h *Outbound) GetStrategy() ConnectionStrategy {
	return h.strategy
}

func connChecker(ctx context.Context, closeFunc func() error) {
	<-ctx.Done()
	closeFunc()
}

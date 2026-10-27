package call

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
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

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.CallOutboundOptions](registry, C.TypeCall, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	ctx          context.Context
	logger       logger.ContextLogger
	options      option.CallOutboundOptions
	dialer       N.Dialer
	bridge       atomic.Pointer[call.Bridge] // set by the connect loop, read by dials and close
	startHandler func()
	await        chan struct{}
	cancel       context.CancelFunc // stops the connect retries on close
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.CallOutboundOptions) (adapter.Outbound, error) {
	if options.JoinLink == "" {
		return nil, E.New("missing join_link")
	}
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
	ob := &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeCall, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		ctx:     ctx,
		logger:  logger,
		options: options,
		dialer:  outboundDialer,
		await:   make(chan struct{}),
	}
	dnsRouter := service.FromContext[adapter.DNSRouter](ctx)
	connectCtx, cancel := context.WithCancel(ctx)
	ob.cancel = cancel
	ob.startHandler = func() {
		connectWithRetry(connectCtx, logger, func() (*call.Bridge, error) {
			return call.Connect(connectCtx, call.Config{
				Platform:     options.Platform,
				Mode:         options.Mode,
				JoinLink:     options.JoinLink,
				CookieString: options.Cookies.Header(),
				ReadBuffer:   options.ReadBuffer,
				Role:         call.RoleJoiner,
				Dialer:       outboundDialer,
				DNSRouter:    dnsRouter,
				Logger:       logger,
			})
		}, ob.bridge.Store, func() { close(ob.await) })
	}
	return ob, nil
}

func (o *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	scope.Add(func() error {
		o.cancel()
		if bridge := o.bridge.Load(); bridge != nil {
			return bridge.Close()
		}
		return nil
	})
	go o.startHandler()
	return nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if err := o.awaitBridge(ctx); err != nil {
		return nil, err
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		o.logger.InfoContext(ctx, "outbound connection to ", destination)
		conn, err := o.bridge.Load().DialContext(ctx, destination.String())
		if err != nil {
			return nil, err
		}
		return deadline.NewConn(conn), nil
	default:
		return nil, E.New("call: unsupported network: ", network)
	}
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if err := o.awaitBridge(ctx); err != nil {
		return nil, err
	}
	o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	conn, err := o.bridge.Load().ListenPacket(ctx, destination.String())
	if err != nil {
		return nil, err
	}
	return bufio.NewUnbindPacketConnWithAddr(conn, destination), nil
}

func (o *Outbound) awaitBridge(ctx context.Context) error {
	select {
	case <-o.await:
	case <-ctx.Done():
		return ctx.Err()
	}
	if o.bridge.Load() == nil {
		return E.New("call: not connected to the call yet")
	}
	return nil
}

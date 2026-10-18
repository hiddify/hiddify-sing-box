package mtproxy

import (
	"context"
	"net"

	"github.com/dolonet/mtg-multi/antireplay"
	"github.com/dolonet/mtg-multi/events"
	"github.com/dolonet/mtg-multi/mtglib"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.MTProxyInboundOptions](registry, C.TypeMTProxy, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx      context.Context
	router   adapter.ConnectionRouterEx
	logger   logger.ContextLogger
	listener *listener.Listener
	proxy    *mtglib.Proxy
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MTProxyInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeMTProxy, tag),
		ctx:     ctx,
		router:  router,
		logger:  logger,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Listen:  options.ListenOptions,
		}),
	}
	mtgLogger := NewLoggerAdapter(logger)
	secrets := make(map[string]mtglib.Secret, len(options.Users))
	for _, user := range options.Users {
		secret := mtglib.Secret{}
		err := secret.Set(user.Secret)
		if err != nil {
			return nil, err
		}
		secrets[user.Name] = secret
	}
	opts := mtglib.ProxyOpts{
		Logger:          mtgLogger,
		Network:         NewNetworkAdapter(ctx, NewDialer(inbound.newConnection)),
		AntiReplayCache: antireplay.NewNoop(),
		EventStream:     events.NewNoopStream(),

		Secrets:                     secrets,
		Concurrency:                 options.GetConcurrency(),
		DomainFrontingPort:          options.GetDomainFrontingPort(),
		DomainFrontingHost:          options.DomainFrontingHost,
		DomainFrontingProxyProtocol: options.DomainFrontingProxyProtocol,
		PreferIP:                    options.GetPreferIP(),
		AutoUpdate:                  options.AutoUpdate,

		AllowFallbackOnUnknownDC: options.AllowFallbackOnUnknownDC,
		TolerateTimeSkewness:     options.TolerateTimeSkewness.Build(),
		IdleTimeout:              options.GetIdleTimeout(),
		HandshakeTimeout:         options.GetHandshakeTimeout(),

		DoppelGangerURLs:    options.DoppelGangerURLs,
		DoppelGangerPerRaid: options.GetDoppelGangerPerRaid(),
		DoppelGangerEach:    options.GetDoppelGangerEach(),
		DoppelGangerDRS:     options.DoppelGangerDRS,

		ThrottleMaxConnections: options.ThrottleMaxConnections,
		ThrottleCheckInterval:  options.GetThrottleCheckInterval(),
	}
	proxy, err := mtglib.NewProxy(opts)
	if err != nil {
		return nil, E.New("cannot create a proxy: ", err)
	}
	inbound.proxy = proxy
	return inbound, nil
}

func (n *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	scope.Add(func() error {
		n.proxy.Shutdown()
		return nil
	})
	listener, err := n.listener.ListenTCP()
	if err != nil {
		return err
	}
	scope.Add(n.listener.Close)
	go n.proxy.Serve(listener)
	return nil
}

func (h *Inbound) UpdateUsers(users []option.MTProxyUser) {
	secrets := make(map[string]mtglib.Secret, len(users))
	for _, user := range users {
		secret := mtglib.Secret{}
		err := secret.Set(user.Secret)
		if err != nil {
			return
		}
		secrets[user.Name] = secret
	}
	h.proxy.UpdateUsers(secrets)
}

func (h *Inbound) newConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	h.logger.InfoContext(ctx, "[", metadata.User, "] inbound connection to ", metadata.Destination)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

package trusttunnel

import (
	"context"
	"errors"
	"net"
	"net/http"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/congestion"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/trusttunnel"
	"github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	aTLS "github.com/sagernet/sing/common/tls"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.TrustTunnelInboundOptions](registry, C.TypeTrustTunnel, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx            context.Context
	router         adapter.Router
	logger         logger.ContextLogger
	options        option.TrustTunnelInboundOptions
	listener       *listener.Listener
	service        *trusttunnel.Service
	httpServer     *http.Server
	http3Server    *http3.Server
	httpTLSConfig  tls.ServerConfig
	http3TLSConfig tls.ServerConfig
	network        []string
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TrustTunnelInboundOptions) (adapter.Inbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	networkList := options.Network.Build()
	if len(networkList) == 0 {
		networkList = []string{N.NetworkTCP}
	}
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeTrustTunnel, tag),
		ctx:     ctx,
		router:  router,
		logger:  logger,
		options: options,
		network: networkList,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Listen:  options.ListenOptions,
		}),
	}
	service := trusttunnel.NewService(trusttunnel.ServiceOptions{
		Ctx:     ctx,
		Logger:  logger,
		Handler: (*inboundHandler)(inbound),
	})
	userMap := make(map[string]string, len(options.Users))
	for _, u := range options.Users {
		userMap[u.Name] = u.Password
	}
	service.UpdateUsers(userMap)
	inbound.service = service
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	scope.Add(h.listener.Close)
	var err error
	if common.Contains(h.network, N.NetworkTCP) {
		h.httpTLSConfig, err = tls.NewServer(h.ctx, h.logger, common.PtrValueOrDefault(h.options.TLS))
		if err != nil {
			return err
		}
		if len(h.httpTLSConfig.NextProtos()) == 0 {
			h.httpTLSConfig.SetNextProtos([]string{http2.NextProtoTLS})
		} else if !common.Contains(h.httpTLSConfig.NextProtos(), http2.NextProtoTLS) {
			h.httpTLSConfig.SetNextProtos(append([]string{http2.NextProtoTLS}, h.httpTLSConfig.NextProtos()...))
		}
		listener, err := h.listener.ListenTCP()
		if err != nil {
			return err
		}
		h.httpServer = &http.Server{
			Handler: h2c.NewHandler(h.service, &http2.Server{}),
			BaseContext: func(net.Listener) context.Context {
				return h.ctx
			},
		}
		err = h.httpTLSConfig.Start()
		if err != nil {
			return err
		}
		scope.Add(h.httpTLSConfig.Close)
		scope.Add(h.httpServer.Close)
		listener = aTLS.NewListener(listener, h.httpTLSConfig)
		go func() {
			sErr := h.httpServer.Serve(listener)
			if sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
				h.logger.Error("HTTP server error: ", sErr)
			}
		}()
	}
	if common.Contains(h.network, N.NetworkUDP) {
		h.http3TLSConfig, err = tls.NewServer(h.ctx, h.logger, common.PtrValueOrDefault(h.options.TLS))
		if err != nil {
			return err
		}
		if err := qtls.ConfigureHTTP3(h.http3TLSConfig); err != nil {
			return err
		}
		err = h.http3TLSConfig.Start()
		if err != nil {
			return err
		}
		scope.Add(h.http3TLSConfig.Close)
		udpConn, err := h.listener.ListenUDP()
		if err != nil {
			return err
		}
		congestionControlFactory, err := congestion.NewCongestionControl(
			h.options.CongestionController,
			h.options.CWND,
			ntp.TimeFuncFromContext(h.ctx),
		)
		if err != nil {
			return err
		}
		h.http3Server = &http3.Server{
			Handler: h.service,
			ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
				conn.SetCongestionControl(congestionControlFactory(conn))
				return ctx
			},
		}
		quicListener, err := qtls.ListenEarly(udpConn, h.http3TLSConfig, &quic.Config{
			MaxIdleTimeout:          trusttunnel.DefaultSessionTimeout * 2,
			MaxIncomingStreams:      1 << 60,
			Allow0RTT:               true,
			DisablePathMTUDiscovery: h.options.DisablePathMTUDiscovery,
		})
		if err != nil {
			return err
		}
		scope.Add(h.http3Server.Close)
		go func() {
			_ = h.http3Server.ServeListener(quicListener)
		}()
	}
	return nil
}

func (h *Inbound) UpdateUsers(users []option.TrustTunnelUser) {
	userMap := make(map[string]string, len(users))
	for _, u := range users {
		userMap[u.Name] = u.Password
	}
	h.service.UpdateUsers(userMap)
}

type inboundHandler Inbound

func (h *inboundHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	var inboundCtx adapter.InboundContext
	inboundCtx.Inbound = h.Tag()
	inboundCtx.InboundType = h.Type()
	//nolint:staticcheck
	inboundCtx.InboundDetour = h.listener.ListenOptions().Detour
	inboundCtx.Source = metadata.Source
	inboundCtx.Destination = metadata.Destination
	if userName, _ := auth.UserFromContext[string](ctx); userName != "" {
		inboundCtx.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", inboundCtx.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", inboundCtx.Destination)
	}
	h.router.RouteConnectionEx(ctx, conn, inboundCtx, nil)
	return nil
}

func (h *inboundHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	var inboundCtx adapter.InboundContext
	inboundCtx.Inbound = h.Tag()
	inboundCtx.InboundType = h.Type()
	//nolint:staticcheck
	inboundCtx.InboundDetour = h.listener.ListenOptions().Detour
	inboundCtx.Source = metadata.Source
	inboundCtx.Destination = metadata.Destination
	if userName, _ := auth.UserFromContext[string](ctx); userName != "" {
		inboundCtx.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound packet connection to ", inboundCtx.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound packet connection to ", inboundCtx.Destination)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, inboundCtx, nil)
	return nil
}

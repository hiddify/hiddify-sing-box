package vpn

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	sbUot "github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/service"
)

func RegisterClientEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.VPNClientEndpointOptions](registry, C.TypeVPNClient, NewClientEndpoint)
}

type ClientEndpoint struct {
	outbound.Adapter
	ctx            context.Context
	outbound       adapter.Outbound
	router         adapter.ConnectionRouterEx
	logger         logger.ContextLogger
	address        IPv4
	key            uuid.UUID
	defaultGateway IPv4
	uotClient      *uot.Client
}

func NewClientEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.VPNClientEndpointOptions) (adapter.Endpoint, error) {
	address := options.Address
	if !address.Is4() {
		return nil, E.New("invalid address: ", address)
	}
	key, err := uuid.FromString(options.Key)
	if err != nil {
		return nil, err
	}
	defaultGateway := Loopback.As4()
	if options.DefaultGateway.IsValid() {
		if !options.DefaultGateway.Is4() {
			return nil, E.New("invalid default_gateway: ", options.DefaultGateway)
		}
		defaultGateway = options.DefaultGateway.As4()
	}
	client := &ClientEndpoint{
		Adapter:        outbound.NewAdapter(C.TypeVPNClient, tag, []string{N.NetworkTCP, N.NetworkUDP}, []string{}),
		ctx:            ctx,
		router:         sbUot.NewRouter(router, logger),
		logger:         logger,
		address:        address.As4(),
		key:            key,
		defaultGateway: defaultGateway,
	}
	outboundRegistry := service.FromContext[adapter.OutboundRegistry](ctx)
	outbound, err := outboundRegistry.CreateOutbound(ctx, router, logger, options.Outbound.Tag, options.Outbound.Type, options.Outbound.Options)
	if err != nil {
		return nil, err
	}
	client.outbound = outbound
	client.uotClient = &uot.Client{
		Dialer:  outbound,
		Version: uot.Version,
	}
	return client, nil
}

func (c *ClientEndpoint) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	lifecycle, isLifecycle := c.outbound.(adapter.Lifecycle)
	if isLifecycle {
		err := scope.Start("outbound/"+c.outbound.Type()+"["+c.outbound.Tag()+"]", lifecycle, stage)
		if err != nil {
			return err
		}
	}
	if stage != adapter.StartStatePostStart {
		return nil
	}
	for range 5 {
		go func() {
			for {
				select {
				case <-scope.Context().Done():
					return
				default:
					err := c.startInboundConn()
					if err != nil {
						c.logger.ErrorContext(c.ctx, err)
						time.Sleep(time.Second * 5)
					}
				}
			}
		}()
	}
	return nil
}

func (c *ClientEndpoint) References() []string {
	referrer, isReferrer := c.outbound.(adapter.Referrer)
	if isReferrer {
		return referrer.References()
	}
	return c.outbound.Dependencies()
}

func (c *ClientEndpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) == N.NetworkUDP {
		return c.uotClient.DialContext(ctx, network, destination)
	}
	if destination.Addr.Is4() && destination.Addr.As4() == c.address {
		return nil, E.New("routing loop on ", destination.Addr)
	}
	conn, err := c.outbound.DialContext(ctx, N.NetworkTCP, Destination)
	if err != nil {
		return nil, err
	}
	gateway := c.defaultGateway
	if metadata := adapter.ContextFrom(ctx); metadata != nil {
		if metadata.Gateway != nil {
			gateway = metadata.Gateway.As4()
			if gateway == c.address {
				return nil, E.New("routing loop on ", destination.Addr)
			}
		}
	}
	err = WriteClientRequest(
		conn,
		&ClientRequest{
			Key:         c.key,
			Command:     CommandTCP,
			Gateway:     gateway,
			Destination: destination,
		},
	)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *ClientEndpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return c.uotClient.ListenPacket(ctx, destination)
}

func (c *ClientEndpoint) startInboundConn() error {
	conn, err := c.outbound.DialContext(c.ctx, N.NetworkTCP, Destination)
	if err != nil {
		return err
	}
	err = WriteClientRequest(conn, &ClientRequest{Key: c.key, Command: CommandInbound, Destination: Destination})
	if err != nil {
		return err
	}
	request, err := ReadServerRequest(conn)
	if err != nil {
		return err
	}
	if request.Source == c.address {
		return E.New("routing loop")
	}
	metadata := adapter.InboundContext{
		Inbound:     c.Tag(),
		Source:      M.Socksaddr{Addr: netip.AddrFrom4(request.Source)},
		Destination: request.Destination,
	}
	go c.router.RouteConnectionEx(c.ctx, conn, metadata, func(it error) {})
	return nil
}

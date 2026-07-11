package tunnel

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterClientEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.TunnelClientEndpointOptions](registry, C.TypeTunnelClient, NewClientEndpoint)
}

type ClientEndpoint struct {
	outbound.Adapter
	ctx      context.Context
	outbound adapter.Outbound
	router   adapter.ConnectionRouterEx
	logger   logger.ContextLogger
	uuid     uuid.UUID
	key      uuid.UUID
}

func NewClientEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TunnelClientEndpointOptions) (adapter.Endpoint, error) {
	clientUUID, err := uuid.FromString(options.UUID)
	if err != nil {
		return nil, err
	}
	clientKey, err := uuid.FromString(options.Key)
	if err != nil {
		return nil, err
	}
	client := &ClientEndpoint{
		Adapter: outbound.NewAdapter(C.TypeTunnelClient, tag, []string{N.NetworkTCP}, []string{}),
		ctx:     ctx,
		router:  router,
		logger:  logger,
		uuid:    clientUUID,
		key:     clientKey,
	}
	outboundRegistry := service.FromContext[adapter.OutboundRegistry](ctx)
	outbound, err := outboundRegistry.CreateOutbound(ctx, router, logger, options.Outbound.Tag, options.Outbound.Type, options.Outbound.Options)
	if err != nil {
		return nil, err
	}
	client.outbound = outbound
	return client, nil
}

func (c *ClientEndpoint) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	for range 5 {
		go func() {
			for {
				select {
				case <-c.ctx.Done():
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

func (c *ClientEndpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != N.NetworkTCP {
		return nil, os.ErrInvalid
	}
	var destinationUUID *uuid.UUID
	if metadata := adapter.ContextFrom(ctx); metadata != nil {
		if metadata.TunnelDestination != "" {
			uuid, err := uuid.FromString(metadata.TunnelDestination)
			if err != nil {
				return nil, err
			}
			destinationUUID = &uuid
		}
	}
	if destinationUUID == nil {
		return nil, E.New("tunnel destination not set")
	}
	if *destinationUUID == c.uuid {
		return nil, E.New("routing loop")
	}
	conn, err := c.outbound.DialContext(ctx, N.NetworkTCP, Destination)
	if err != nil {
		return nil, err
	}
	err = WriteRequest(conn, &Request{UUID: c.key, Command: CommandTCP, DestinationUUID: *destinationUUID, Destination: destination})
	return conn, err
}

func (c *ClientEndpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (c *ClientEndpoint) Close() error {
	return common.Close(c.outbound)
}

func (c *ClientEndpoint) startInboundConn() error {
	conn, err := c.outbound.DialContext(c.ctx, N.NetworkTCP, Destination)
	if err != nil {
		return err
	}
	err = WriteRequest(conn, &Request{UUID: c.key, Command: CommandInbound, Destination: Destination})
	if err != nil {
		return err
	}
	request, err := ReadRequest(conn)
	if err != nil {
		return err
	}
	go c.connHandler(conn, request)
	return nil
}

func (c *ClientEndpoint) connHandler(conn net.Conn, request *Request) {
	metadata := adapter.InboundContext{
		Source:      M.ParseSocksaddr(conn.RemoteAddr().String()),
		Destination: request.Destination,
	}
	if request.UUID == c.uuid {
		c.logger.ErrorContext(c.ctx, "routing loop")
		conn.Close()
		return
	}
	metadata.TunnelSource = request.UUID.String()
	c.router.RouteConnectionEx(c.ctx, conn, metadata, func(it error) {})
}

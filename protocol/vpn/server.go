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

func RegisterServerEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.VPNServerEndpointOptions](registry, C.TypeVPNServer, NewServerEndpoint)
}

type ServerEndpoint struct {
	outbound.Adapter
	logger         logger.ContextLogger
	inbounds       []adapter.Inbound
	router         adapter.ConnectionRouterEx
	address        IPv4
	addresses      map[uuid.UUID]IPv4
	keys           map[IPv4]uuid.UUID
	conns          map[IPv4]chan net.Conn
	timeout        time.Duration
	defaultGateway *netip.Addr
	uotClient      *uot.Client
}

func NewServerEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.VPNServerEndpointOptions) (adapter.Endpoint, error) {
	address := options.Address
	if !address.Is4() {
		return nil, E.New("invalid address: ", address)
	}
	server := &ServerEndpoint{
		Adapter: outbound.NewAdapter(C.TypeVPNServer, tag, []string{N.NetworkTCP, N.NetworkUDP}, []string{}),
		logger:  logger,
		router:  sbUot.NewRouter(router, logger),
		address: address.As4(),
	}
	if options.DefaultGateway.IsValid() {
		if !options.DefaultGateway.Is4() {
			return nil, E.New("invalid default_gateway: ", options.DefaultGateway)
		}
		defaultGateway := options.DefaultGateway
		server.defaultGateway = &defaultGateway
	}
	router = NewRouter(router, logger, server.connHandler)
	inboundRegistry := service.FromContext[adapter.InboundRegistry](ctx)
	inbounds := make([]adapter.Inbound, len(options.Inbounds))
	for i, inboundOptions := range options.Inbounds {
		inbound, err := inboundRegistry.Create(ctx, router, logger, inboundOptions.Tag, inboundOptions.Type, inboundOptions.Options)
		if err != nil {
			return nil, err
		}
		inbounds[i] = inbound
	}
	server.inbounds = inbounds
	server.addresses = make(map[uuid.UUID]IPv4, len(options.Users))
	server.keys = make(map[IPv4]uuid.UUID, len(options.Users))
	server.conns = make(map[IPv4]chan net.Conn)
	for _, user := range options.Users {
		key, err := uuid.FromString(user.Key)
		if err != nil {
			return nil, err
		}
		if !user.Address.Is4() {
			return nil, E.New("invalid address: ", user.Address)
		}
		address := user.Address.As4()
		server.addresses[key] = address
		server.keys[address] = key
		server.conns[address] = make(chan net.Conn, 10)
	}
	if options.ConnectTimeout != 0 {
		server.timeout = time.Duration(options.ConnectTimeout)
	} else {
		server.timeout = C.TCPConnectTimeout
	}
	server.uotClient = &uot.Client{
		Dialer:  server,
		Version: uot.Version,
	}
	return server, nil
}

func (s *ServerEndpoint) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	for _, inbound := range s.inbounds {
		err := scope.Start("inbound/"+inbound.Type()+"["+inbound.Tag()+"]", inbound, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *ServerEndpoint) References() []string {
	var references []string
	for _, inbound := range s.inbounds {
		referrer, isReferrer := inbound.(adapter.Referrer)
		if isReferrer {
			references = append(references, referrer.References()...)
		}
	}
	return references
}

func (s *ServerEndpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) == N.NetworkUDP {
		return s.uotClient.DialContext(ctx, network, destination)
	}
	source := s.address
	var gateway *netip.Addr
	if metadata := adapter.ContextFrom(ctx); metadata != nil {
		if metadata.Source.IsIPv4() {
			address := metadata.Source.Addr.As4()
			if _, ok := s.conns[address]; ok {
				source = address
			}
		}
		if metadata.Gateway != nil {
			gateway = metadata.Gateway
		}
	}
	if gateway == nil {
		if s.defaultGateway != nil {
			gateway = s.defaultGateway
		} else if destination.IsIPv4() {
			gateway = &destination.Addr
			destination = M.Socksaddr{
				Addr: Loopback,
				Port: destination.Port,
			}
		} else {
			return nil, E.New("missing gateway")
		}
	}
	if destination.Addr.Compare(*gateway) == 0 {
		destination = M.Socksaddr{
			Addr: Loopback,
			Port: destination.Port,
		}
	}
	if gateway.Compare(Loopback) == 0 {
		return nil, E.New("invalid gateway")
	}
	ch, ok := s.conns[gateway.As4()]
	if !ok {
		return nil, E.New("user with address ", gateway, " not found")
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		select {
		case conn := <-ch:
			err := WriteServerRequest(conn, &ServerRequest{Source: source, Destination: destination})
			if err != nil {
				conn.Close()
				s.logger.ErrorContext(ctx, err)
				continue
			}
			return conn, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (s *ServerEndpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return s.uotClient.ListenPacket(ctx, destination)
}

func (s *ServerEndpoint) connHandler(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
	if metadata.Destination != Destination {
		s.router.RouteConnectionEx(ctx, conn, metadata, onClose)
		return nil
	}
	request, err := ReadClientRequest(conn)
	if err != nil {
		return err
	}
	if request.Command == CommandInbound {
		address, ok := s.addresses[request.Key]
		if !ok {
			return E.New("key ", request.Key.String(), " not found")
		}
		ch := s.conns[address]
		select {
		case ch <- conn:
		default:
			oldConn := <-ch
			oldConn.Close()
			ch <- conn
		}
		return nil
	}
	if request.Command == CommandTCP {
		source, ok := s.addresses[request.Key]
		if !ok {
			return E.New("key ", request.Key, " not found")
		}
		if request.Destination.Addr.Is4() && source == request.Destination.Addr.As4() {
			return E.New("routing loop on ", request.Destination)
		}
		metadata.Inbound = s.Tag()
		metadata.InboundType = C.TypeVPNServer
		metadata.Source = M.Socksaddr{Addr: netip.AddrFrom4(source)}
		if request.Destination.Addr.Is4() && request.Destination.Addr.As4() == s.address {
			metadata.Destination = M.Socksaddr{
				Addr: Loopback,
				Port: request.Destination.Port,
			}
		} else {
			metadata.Destination = request.Destination
			if request.Gateway != s.address && request.Gateway != Loopback.As4() {
				addr := netip.AddrFrom4(request.Gateway)
				metadata.Gateway = &addr
			}
		}
		s.router.RouteConnectionEx(ctx, conn, metadata, onClose)
		return nil
	}
	return E.New("command ", request.Command, " not found")
}

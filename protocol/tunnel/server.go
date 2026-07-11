package tunnel

import (
	"context"
	"net"
	"os"
	"sync"
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

func RegisterServerEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.TunnelServerEndpointOptions](registry, C.TypeTunnelServer, NewServerEndpoint)
}

type ServerEndpoint struct {
	outbound.Adapter
	logger  logger.ContextLogger
	inbound adapter.Inbound
	router  adapter.Router
	uuid    uuid.UUID
	users   map[uuid.UUID]uuid.UUID
	keys    map[uuid.UUID]uuid.UUID
	conns   map[uuid.UUID]chan net.Conn
	timeout time.Duration

	mtx sync.Mutex
}

func NewServerEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TunnelServerEndpointOptions) (adapter.Endpoint, error) {
	serverUUID, err := uuid.FromString(options.UUID)
	if err != nil {
		return nil, err
	}
	server := &ServerEndpoint{
		Adapter: outbound.NewAdapter(C.TypeTunnelServer, tag, []string{N.NetworkTCP}, []string{}),
		logger:  logger,
		router:  router,
		uuid:    serverUUID,
	}
	inboundRegistry := service.FromContext[adapter.InboundRegistry](ctx)
	inbound, err := inboundRegistry.Create(ctx, NewRouter(router, logger, server.connHandler), logger, options.Inbound.Tag, options.Inbound.Type, options.Inbound.Options)
	if err != nil {
		return nil, err
	}
	server.inbound = inbound
	server.users = make(map[uuid.UUID]uuid.UUID, len(options.Users))
	server.keys = make(map[uuid.UUID]uuid.UUID, len(options.Users))
	server.conns = make(map[uuid.UUID]chan net.Conn)
	for _, user := range options.Users {
		key, err := uuid.FromString(user.Key)
		if err != nil {
			return nil, err
		}
		uuid, err := uuid.FromString(user.UUID)
		if err != nil {
			return nil, err
		}
		server.users[key] = uuid
		server.keys[uuid] = key
		server.conns[uuid] = make(chan net.Conn, 10)
	}
	if options.ConnectTimeout != 0 {
		server.timeout = time.Duration(options.ConnectTimeout)
	} else {
		server.timeout = C.TCPConnectTimeout
	}
	return server, nil
}

func (s *ServerEndpoint) Start(stage adapter.StartStage) error {
	return s.inbound.Start(stage)
}

func (s *ServerEndpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != N.NetworkTCP {
		return nil, os.ErrInvalid
	}
	var sourceUUID *uuid.UUID
	var ch chan net.Conn
	if metadata := adapter.ContextFrom(ctx); metadata != nil {
		if metadata.TunnelDestination != "" {
			tunnelDestination, err := uuid.FromString(metadata.TunnelDestination)
			if err != nil {
				return nil, err
			}
			s.mtx.Lock()
			var ok bool
			ch, ok = s.conns[tunnelDestination]
			if !ok {
				return nil, E.New("user ", metadata.TunnelDestination, " not found")
			}
			s.mtx.Unlock()
		}
		if metadata.TunnelSource != "" {
			tunnelSource, err := uuid.FromString(metadata.TunnelSource)
			if err != nil {
				return nil, err
			}
			sourceUUID = &tunnelSource
		}
	}
	if ch == nil {
		return nil, E.New("tunnel destination not set")
	}
	if sourceUUID == nil {
		sourceUUID = &s.uuid
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
			err := WriteRequest(conn, &Request{UUID: *sourceUUID, Command: CommandTCP, Destination: destination})
			if err != nil {
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
	return nil, os.ErrInvalid
}

func (s *ServerEndpoint) Close() error {
	return common.Close(s.inbound)
}

func (s *ServerEndpoint) connHandler(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
	if metadata.Destination != Destination {
		s.router.RouteConnectionEx(ctx, conn, metadata, onClose)
		return nil
	}
	request, err := ReadRequest(conn)
	if err != nil {
		return err
	}
	if request.Command == CommandInbound {
		s.mtx.Lock()
		defer s.mtx.Unlock()
		uuid, ok := s.users[request.UUID]
		if !ok {
			return E.New("key ", request.UUID.String(), " not found")
		}
		ch := s.conns[uuid]
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
		sourceUUID, ok := s.users[request.UUID]
		if !ok {
			return E.New("key ", request.UUID, " not found")
		}
		if sourceUUID == request.DestinationUUID {
			return E.New("routing loop on ", sourceUUID)
		}
		s.mtx.Lock()
		if request.DestinationUUID != s.uuid {
			_, ok = s.keys[request.DestinationUUID]
			if !ok {
				return E.New("user ", sourceUUID, " not found")
			}
		}
		s.mtx.Unlock()
		metadata.Inbound = s.Tag()
		metadata.InboundType = C.TypeTunnelServer
		metadata.Destination = request.Destination
		metadata.TunnelSource = sourceUUID.String()
		metadata.TunnelDestination = request.DestinationUUID.String()
		s.router.RouteConnectionEx(ctx, conn, metadata, onClose)
		return nil
	}
	return E.New("command ", request.Command, " not found")
}

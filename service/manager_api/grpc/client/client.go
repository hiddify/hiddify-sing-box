package client

import (
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	pb "github.com/sagernet/sing-box/service/manager_api/grpc/manager"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type Client struct {
	boxService.Adapter

	ctx     context.Context
	logger  log.ContextLogger
	dialer  N.Dialer
	creds   credentials.TransportCredentials
	options option.ManagerAPIClientOptions

	conn *grpc.ClientConn
	mtx  sync.Mutex
}

func NewClient(ctx context.Context, logger log.ContextLogger, tag string, options option.ManagerAPIClientOptions) (*Client, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	creds := insecure.NewCredentials()
	if options.TLS != nil {
		tlsConfig, err := tls.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		creds = &tlsCreds{config: tlsConfig}
	}
	return &Client{
		Adapter: boxService.NewAdapter(C.TypeManagerAPI, tag),
		ctx:     ctx,
		logger:  logger,
		dialer:  outboundDialer,
		creds:   creds,
		options: options,
	}, nil
}

func (s *Client) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	scope.Add(func() error {
		s.mtx.Lock()
		defer s.mtx.Unlock()
		if s.conn != nil {
			return s.conn.Close()
		}
		return nil
	})
	return nil
}
func (s *Client) client() (pb.ManagerClient, error) {
	conn, err := s.getConn()
	if err != nil {
		return nil, err
	}
	return pb.NewManagerClient(conn), nil
}

func (s *Client) getConn() (*grpc.ClientConn, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if s.conn != nil {
		state := s.conn.GetState()
		if state != connectivity.Shutdown && state != connectivity.TransientFailure {
			return s.conn, nil
		}
	}
	conn, err := grpc.NewClient(
		s.options.ServerOptions.Build().String(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return s.dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(addr))
		}),
		grpc.WithTransportCredentials(s.creds),
	)
	if err != nil {
		return nil, err
	}
	s.conn = conn
	return conn, nil
}

func (s *Client) callContext() context.Context {
	if s.options.APIKey == "" {
		return s.ctx
	}
	return metadata.AppendToOutgoingContext(s.ctx, "authorization", s.options.APIKey)
}

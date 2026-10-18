package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	CM "github.com/sagernet/sing-box/service/manager/constant"
	pb "github.com/sagernet/sing-box/service/manager_api/grpc/manager"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	"github.com/sagernet/sing/service"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type Server struct {
	pb.UnimplementedManagerServer
	boxService.Adapter

	ctx        context.Context
	logger     log.ContextLogger
	listener   *listener.Listener
	tlsConfig  tls.ServerConfig
	grpcServer *grpc.Server
	manager    CM.Manager
	options    option.ManagerAPIServerOptions

	mtx sync.Mutex
}

func NewServer(ctx context.Context, logger log.ContextLogger, tag string, options option.ManagerAPIServerOptions) (*Server, error) {
	if options.APIKey == "" {
		return nil, E.New("missing api key")
	}
	return &Server{
		Adapter: boxService.NewAdapter(C.TypeManagerAPI, tag),
		ctx:     ctx,
		logger:  logger,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Network: []string{N.NetworkTCP},
			Listen:  options.ListenOptions,
		}),
		options: options,
	}, nil
}

func (s *Server) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	boxManager := service.FromContext[adapter.ServiceManager](s.ctx)
	managerService, ok := boxManager.Get(s.options.Manager)
	if !ok {
		return E.New("manager ", s.options.Manager, " not found")
	}
	s.manager, ok = managerService.(CM.Manager)
	if !ok {
		return E.New("invalid ", s.options.Manager, " manager")
	}
	if s.options.TLS != nil {
		tlsConfig, err := tls.NewServer(s.ctx, s.logger, common.PtrValueOrDefault(s.options.TLS))
		if err != nil {
			return err
		}
		s.tlsConfig = tlsConfig
	}
	if s.tlsConfig != nil {
		if err := s.tlsConfig.Start(); err != nil {
			return E.Cause(err, "create TLS config")
		}
		scope.Add(s.tlsConfig.Close)
	}
	tcpListener, err := s.listener.ListenTCP()
	if err != nil {
		return err
	}
	scope.Add(s.listener.Close)
	if s.tlsConfig != nil {
		if !common.Contains(s.tlsConfig.NextProtos(), http2.NextProtoTLS) {
			s.tlsConfig.SetNextProtos(append([]string{"h2"}, s.tlsConfig.NextProtos()...))
		}
		tcpListener = aTLS.NewListener(tcpListener, s.tlsConfig)
	}
	s.grpcServer = grpc.NewServer(
		grpc.ChainUnaryInterceptor(s.unaryAuthInterceptor, unaryErrorInterceptor),
		grpc.StreamInterceptor(s.streamAuthInterceptor),
	)
	pb.RegisterManagerServer(s.grpcServer, s)
	scope.Add(func() error {
		s.grpcServer.GracefulStop()
		return nil
	})
	go func() {
		if err := s.grpcServer.Serve(tcpListener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			s.logger.Error("serve error: ", err)
		}
	}()
	return nil
}

func (s *Server) unaryAuthInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if err := s.authorize(ctx); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

func (s *Server) streamAuthInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := s.authorize(ss.Context()); err != nil {
		return err
	}
	return handler(srv, ss)
}

func unaryErrorInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	resp, err := handler(ctx, req)
	if err == CM.ErrNotFound {
		return resp, status.Error(codes.NotFound, err.Error())
	}
	return resp, err
}

func (s *Server) authorize(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing api key")
	}
	values := md.Get("authorization")
	if len(values) == 0 {
		return status.Error(codes.Unauthenticated, "missing api key")
	}
	if subtle.ConstantTimeCompare([]byte(values[0]), []byte(s.options.APIKey)) == 0 {
		return status.Error(codes.Unauthenticated, "invalid api key")
	}
	return nil
}

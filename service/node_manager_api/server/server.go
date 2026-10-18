package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	CM "github.com/sagernet/sing-box/service/manager/constant"
	pb "github.com/sagernet/sing-box/service/node_manager_api/manager"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	"github.com/sagernet/sing/service"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type APIServer struct {
	pb.UnimplementedManagerServer
	boxService.Adapter

	ctx        context.Context
	logger     log.ContextLogger
	listener   *listener.Listener
	tlsConfig  tls.ServerConfig
	grpcServer *grpc.Server
	manager    CM.NodeManager
	options    option.NodeManagerAPIServerOptions

	mtx sync.Mutex
}

func NewAPIServer(ctx context.Context, logger log.ContextLogger, tag string, options option.NodeManagerAPIServerOptions) (*APIServer, error) {
	if options.APIKey == "" {
		return nil, E.New("missing api key")
	}
	return &APIServer{
		Adapter: boxService.NewAdapter(C.TypeManager, tag),
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

func (s *APIServer) AddNode(node *pb.Node, stream grpc.ServerStreamingServer[pb.NodeData]) error {
	remoteNode, errChan := NewRemoteNode(s.ctx, s.logger, stream)
	err := s.manager.AddNode(node.Uuid, remoteNode)
	if err != nil {
		if err == CM.ErrNotFound {
			return err
		} else {
			s.logger.Error(err)
			return E.New("internal error")
		}
	}
	return <-errChan
}

func (s *APIServer) AcquireLock(ctx context.Context, request *pb.AcquireLockRequest) (*pb.LockData, error) {
	handleId, err := s.manager.AcquireLock(int(request.LimiterId), request.Id)
	if err != nil {
		return nil, err
	}
	return &pb.LockData{HandleId: handleId}, nil
}

func (s *APIServer) RefreshLock(ctx context.Context, data *pb.LockData) (*pb.Empty, error) {
	return nil, s.manager.RefreshLock(int(data.LimiterId), data.Id, data.HandleId)
}

func (s *APIServer) ReleaseLock(ctx context.Context, data *pb.LockData) (*pb.Empty, error) {
	return nil, s.manager.ReleaseLock(int(data.LimiterId), data.Id, data.HandleId)
}

func (s *APIServer) AddTrafficUsage(ctx context.Context, request *pb.TrafficUsageRequest) (*pb.TrafficUsageReply, error) {
	remaining, err := s.manager.AddTrafficUsage(int(request.LimiterId), request.N)
	if err != nil {
		return nil, err
	}
	return &pb.TrafficUsageReply{Remaining: remaining}, nil
}

func (s *APIServer) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	boxManager := service.FromContext[adapter.ServiceManager](s.ctx)
	service, ok := boxManager.Get(s.options.Manager)
	if !ok {
		return E.New("manager ", s.options.Manager, " not found")
	}
	s.manager, ok = service.(CM.NodeManager)
	if !ok {
		return E.New("invalid", s.options.Manager, " manager")
	}
	if s.options.TLS != nil {
		tlsConfig, err := tls.NewServer(s.ctx, s.logger, common.PtrValueOrDefault(s.options.TLS))
		if err != nil {
			return err
		}
		s.tlsConfig = tlsConfig
	}
	if s.tlsConfig != nil {
		err := s.tlsConfig.Start()
		if err != nil {
			return E.Cause(err, "create TLS config")
		}
	}
	tcpListener, err := s.listener.ListenTCP()
	if err != nil {
		return err
	}
	if s.tlsConfig != nil {
		if !common.Contains(s.tlsConfig.NextProtos(), http2.NextProtoTLS) {
			s.tlsConfig.SetNextProtos(append([]string{"h2"}, s.tlsConfig.NextProtos()...))
		}
		tcpListener = aTLS.NewListener(tcpListener, s.tlsConfig)
	}
	keepAliveTime := time.Duration(s.options.KeepAlive)
	if keepAliveTime <= 0 {
		keepAliveTime = 10 * time.Second
	}
	keepAliveTimeout := time.Duration(s.options.KeepAliveTimeout)
	if keepAliveTimeout <= 0 {
		keepAliveTimeout = 5 * time.Second
	}
	s.grpcServer = grpc.NewServer(
		grpc.ChainUnaryInterceptor(s.unaryAuthInterceptor),
		grpc.StreamInterceptor(s.streamAuthInterceptor),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    keepAliveTime,
			Timeout: keepAliveTimeout,
		}),
	)
	pb.RegisterManagerServer(s.grpcServer, s)
	go func() {
		err = s.grpcServer.Serve(tcpListener)
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			s.logger.Error("serve error: ", err)
		}
	}()
	return nil
}

func (s *APIServer) unaryAuthInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if err := s.authorize(ctx); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

func (s *APIServer) streamAuthInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := s.authorize(ss.Context()); err != nil {
		return err
	}
	return handler(srv, ss)
}

func (s *APIServer) authorize(ctx context.Context) error {
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

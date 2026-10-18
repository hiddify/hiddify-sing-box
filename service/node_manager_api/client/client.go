package client

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	CM "github.com/sagernet/sing-box/service/manager/constant"
	pb "github.com/sagernet/sing-box/service/node_manager_api/manager"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type APIClient struct {
	boxService.Adapter

	ctx     context.Context
	logger  log.ContextLogger
	dialer  N.Dialer
	creds   credentials.TransportCredentials
	options option.NodeManagerAPIClientOptions

	conn *grpc.ClientConn

	mtx sync.Mutex
}

func NewAPIClient(ctx context.Context, logger log.ContextLogger, tag string, options option.NodeManagerAPIClientOptions) (*APIClient, error) {
	if options.APIKey == "" {
		return nil, E.New("missing api key")
	}
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
		creds = &tlsCreds{tlsConfig}
	}
	return &APIClient{
		Adapter: boxService.NewAdapter(C.TypeManager, tag),
		ctx:     metadata.AppendToOutgoingContext(ctx, "authorization", options.APIKey),
		logger:  logger,
		dialer:  outboundDialer,
		creds:   creds,
		options: options,
	}, nil
}

func (s *APIClient) AddNode(uuid string, node CM.ConnectedNode) error {
	go func() {
		isRetry := false
		for {
			if !isRetry {
				select {
				case <-s.ctx.Done():
					return
				default:
					isRetry = true
				}
			} else {
				select {
				case <-time.After(5 * time.Second):
					break
				case <-s.ctx.Done():
					return
				}
			}
			conn, err := s.getConn()
			if err != nil {
				s.logger.Error(err)
				continue
			}
			client := pb.NewManagerClient(conn)
			stream, err := client.AddNode(s.ctx, &pb.Node{Uuid: uuid})
			if err != nil {
				s.logger.Error(err)
				continue
			}
			err = s.handler(node, stream)
			if err != nil {
				s.logger.Error(err)
				continue
			}
		}
	}()
	return nil
}

func (s *APIClient) AcquireLock(limiterId int, id string) (string, error) {
	conn, err := s.getConn()
	if err != nil {
		return "", err
	}
	client := pb.NewManagerClient(conn)
	lockReply, err := client.AcquireLock(s.ctx, &pb.AcquireLockRequest{LimiterId: int32(limiterId), Id: id})
	if err != nil {
		return "", err
	}
	return lockReply.HandleId, err
}

func (s *APIClient) RefreshLock(limiterId int, id string, handleId string) error {
	conn, err := s.getConn()
	if err != nil {
		return err
	}
	client := pb.NewManagerClient(conn)
	_, err = client.RefreshLock(s.ctx, &pb.LockData{LimiterId: int32(limiterId), Id: id, HandleId: handleId})
	return err
}

func (s *APIClient) ReleaseLock(limiterId int, id string, handleId string) error {
	conn, err := s.getConn()
	if err != nil {
		return err
	}
	client := pb.NewManagerClient(conn)
	_, err = client.ReleaseLock(s.ctx, &pb.LockData{LimiterId: int32(limiterId), Id: id, HandleId: handleId})
	return err
}

func (s *APIClient) AddTrafficUsage(limiterId int, n uint64) (uint64, error) {
	conn, err := s.getConn()
	if err != nil {
		return 0, err
	}
	client := pb.NewManagerClient(conn)
	reply, err := client.AddTrafficUsage(s.ctx, &pb.TrafficUsageRequest{LimiterId: int32(limiterId), N: n})
	if err != nil {
		return 0, err
	}
	return reply.Remaining, nil
}

func (s *APIClient) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}

func (s *APIClient) getConn() (*grpc.ClientConn, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if s.conn != nil {
		state := s.conn.GetState()
		if state != connectivity.Shutdown && state != connectivity.TransientFailure {
			return s.conn, nil
		}
	}
	for {
		conn, err := s.createConn()
		if err != nil {
			return nil, err
		}
		s.conn = conn
		return conn, nil
	}
}

func (s *APIClient) createConn() (*grpc.ClientConn, error) {
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
	return conn, nil
}

func (s *APIClient) handler(node CM.ConnectedNode, stream grpc.ServerStreamingClient[pb.NodeData]) error {
	for {
		data, err := stream.Recv()
		if err != nil {
			return err
		}
		switch data.Op {
		case pb.OpType_updateUser:
			s.logger.DebugContext(s.ctx, "update user")
			node.UpdateUser(s.convertUser(data.Data.(*pb.NodeData_User).User))
		case pb.OpType_updateUsers:
			s.logger.DebugContext(s.ctx, "update users")
			users := data.Data.(*pb.NodeData_Users).Users.Values
			convertedUsers := make([]CM.User, len(users))
			for i, user := range users {
				convertedUsers[i] = s.convertUser(user)
			}
			node.UpdateUsers(convertedUsers)
		case pb.OpType_deleteUser:
			s.logger.DebugContext(s.ctx, "delete user")
			node.DeleteUser(s.convertUser(data.Data.(*pb.NodeData_User).User))

		case pb.OpType_updateConnectionLimiter:
			s.logger.DebugContext(s.ctx, "update connection limiter")
			node.UpdateConnectionLimiter(s.convertConnectionLimiter(data.Data.(*pb.NodeData_ConnectionLimiter).ConnectionLimiter))
		case pb.OpType_updateConnectionLimiters:
			s.logger.DebugContext(s.ctx, "update connection limiters")
			limiters := data.Data.(*pb.NodeData_ConnectionLimiters).ConnectionLimiters.Values
			convertedLimiters := make([]CM.ConnectionLimiter, len(limiters))
			for i, limiter := range limiters {
				convertedLimiters[i] = s.convertConnectionLimiter(limiter)
			}
			node.UpdateConnectionLimiters(convertedLimiters)
		case pb.OpType_deleteConnectionLimiter:
			s.logger.DebugContext(s.ctx, "delete connection limiter")
			node.DeleteConnectionLimiter(s.convertConnectionLimiter(data.Data.(*pb.NodeData_ConnectionLimiter).ConnectionLimiter))

		case pb.OpType_updateBandwidthLimiter:
			s.logger.DebugContext(s.ctx, "update bandwidth limiter")
			node.UpdateBandwidthLimiter(s.convertBandwidthLimiter(data.Data.(*pb.NodeData_BandwidthLimiter).BandwidthLimiter))
		case pb.OpType_updateBandwidthLimiters:
			s.logger.DebugContext(s.ctx, "update bandwidth limiters")
			limiters := data.Data.(*pb.NodeData_BandwidthLimiters).BandwidthLimiters.Values
			convertedLimiters := make([]CM.BandwidthLimiter, len(limiters))
			for i, limiter := range limiters {
				convertedLimiters[i] = s.convertBandwidthLimiter(limiter)
			}
			node.UpdateBandwidthLimiters(convertedLimiters)
		case pb.OpType_deleteBandwidthLimiter:
			s.logger.DebugContext(s.ctx, "delete bandwidth limiter")
			node.DeleteBandwidthLimiter(s.convertBandwidthLimiter(data.Data.(*pb.NodeData_BandwidthLimiter).BandwidthLimiter))

		case pb.OpType_updateTrafficLimiter:
			s.logger.DebugContext(s.ctx, "update traffic limiter")
			node.UpdateTrafficLimiter(s.convertTrafficLimiter(data.Data.(*pb.NodeData_TrafficLimiter).TrafficLimiter))
		case pb.OpType_updateTrafficLimiters:
			s.logger.DebugContext(s.ctx, "update traffic limiters")
			limiters := data.Data.(*pb.NodeData_TrafficLimiters).TrafficLimiters.Values
			convertedLimiters := make([]CM.TrafficLimiter, len(limiters))
			for i, limiter := range limiters {
				convertedLimiters[i] = s.convertTrafficLimiter(limiter)
			}
			node.UpdateTrafficLimiters(convertedLimiters)
		case pb.OpType_deleteTrafficLimiter:
			s.logger.DebugContext(s.ctx, "delete traffic limiter")
			node.DeleteTrafficLimiter(s.convertTrafficLimiter(data.Data.(*pb.NodeData_TrafficLimiter).TrafficLimiter))

		case pb.OpType_updateRateLimiter:
			s.logger.DebugContext(s.ctx, "update rate limiter")
			node.UpdateRateLimiter(s.convertRateLimiter(data.Data.(*pb.NodeData_RateLimiter).RateLimiter))
		case pb.OpType_updateRateLimiters:
			s.logger.DebugContext(s.ctx, "update rate limiters")
			limiters := data.Data.(*pb.NodeData_RateLimiters).RateLimiters.Values
			convertedLimiters := make([]CM.RateLimiter, len(limiters))
			for i, limiter := range limiters {
				convertedLimiters[i] = s.convertRateLimiter(limiter)
			}
			node.UpdateRateLimiters(convertedLimiters)
		case pb.OpType_deleteRateLimiter:
			s.logger.DebugContext(s.ctx, "delete rate limiter")
			node.DeleteRateLimiter(s.convertRateLimiter(data.Data.(*pb.NodeData_RateLimiter).RateLimiter))
		}
	}
}

func (s *APIClient) convertUser(user *pb.User) CM.User {
	return CM.User{
		ID:             int(user.Id),
		Username:       user.Username,
		Inbound:        user.Inbound,
		Type:           user.Type,
		UUID:           user.Uuid,
		Password:       user.Password,
		Secret:         user.Secret,
		AuthorizedKeys: user.AuthorizedKeys,
		Flow:           user.Flow,
		AlterID:        int(user.AlterId),
	}
}

func (s *APIClient) convertBandwidthLimiter(limiter *pb.BandwidthLimiter) CM.BandwidthLimiter {
	return CM.BandwidthLimiter{
		ID:             int(limiter.Id),
		Username:       limiter.Username,
		Outbound:       limiter.Outbound,
		Strategy:       limiter.Strategy,
		ConnectionType: limiter.ConnectionType,
		Mode:           limiter.Mode,
		FlowKeys:       limiter.FlowKeys,
		Speed:          limiter.Speed,
		RawSpeed:       limiter.RawSpeed,
	}
}

func (s *APIClient) convertConnectionLimiter(limiter *pb.ConnectionLimiter) CM.ConnectionLimiter {
	return CM.ConnectionLimiter{
		ID:             int(limiter.Id),
		Username:       limiter.Username,
		Outbound:       limiter.Outbound,
		Strategy:       limiter.Strategy,
		ConnectionType: limiter.ConnectionType,
		LockType:       limiter.LockType,
		Count:          limiter.Count,
	}
}

func (s *APIClient) convertTrafficLimiter(limiter *pb.TrafficLimiter) CM.TrafficLimiter {
	return CM.TrafficLimiter{
		ID:       int(limiter.Id),
		Username: limiter.Username,
		Outbound: limiter.Outbound,
		Strategy: limiter.Strategy,
		Mode:     limiter.Mode,
		RawUsed:  limiter.RawUsed,
		Quota:    limiter.Quota,
		RawQuota: limiter.RawQuota,
	}
}

func (s *APIClient) convertRateLimiter(limiter *pb.RateLimiter) CM.RateLimiter {
	return CM.RateLimiter{
		ID:             int(limiter.Id),
		Username:       limiter.Username,
		Outbound:       limiter.Outbound,
		Strategy:       limiter.Strategy,
		ConnectionType: limiter.ConnectionType,
		Count:          limiter.Count,
		Interval:       limiter.Interval,
	}
}

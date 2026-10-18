//go:build with_manager

package manager

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/service/manager/constant"
	"github.com/sagernet/sing-box/service/manager/repository/main/postgresql"
	"github.com/sagernet/sing-box/service/manager/repository/main/sqlite"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/shtorm-7/go-cache/v2"
	wpconstant "github.com/shtorm-7/workerpool/constant"
	"github.com/shtorm-7/workerpool/pool"
	"github.com/shtorm-7/workerpool/tools"
	"github.com/shtorm-7/workerpool/worker"
)

func RegisterService(registry *boxService.Registry) {
	boxService.Register[option.ManagerServiceOptions](registry, C.TypeManager, NewService)
}

type Service struct {
	boxService.Adapter
	ctx        context.Context
	logger     log.ContextLogger
	repository constant.Repository
	nodes      map[string]constant.ConnectedNode

	limiterLocks map[int]map[string]*cache.Cache[string, struct{}]
	trafficUsage map[int]*TrafficUsage

	defaultValidator *validator.Validate

	broadcastQueue wpconstant.Queue
	broadcastPool  wpconstant.Pool

	mtx         sync.RWMutex
	connLockMtx sync.Mutex
	trafficMtx  sync.Mutex
}

func NewService(ctx context.Context, logger log.ContextLogger, tag string, options option.ManagerServiceOptions) (adapter.Service, error) {
	var repository constant.Repository
	var err error
	switch options.Database.Driver {
	case "postgresql":
		repository, err = postgresql.NewPostgreSQLRepository(ctx, options.Database.DSN)
		if err != nil {
			return nil, err
		}
	case "sqlite":
		repository, err = sqlite.NewSQLiteRepository(ctx, options.Database.DSN)
		if err != nil {
			return nil, err
		}
	default:
		return nil, E.New("unknown driver \"", options.Database.Driver, "\"")
	}
	defaultValidator := validator.New()
	defaultValidator.RegisterStructValidation(func(sl validator.StructLevel) {
		user := sl.Current().Interface().(constant.UserCreate)
		switch user.Type {
		case "vless":
			if user.UUID == "" {
				sl.ReportError(user.UUID, "uuid", "UUID", "required", "")
			}
		case "vmess":
			if user.UUID == "" {
				sl.ReportError(user.UUID, "uuid", "UUID", "required", "")
			}
			if user.AlterID == 0 {
				sl.ReportError(user.AlterID, "alter_id", "AlterID", "required", "")
			}
		case "trojan", "shadowsocks", "hysteria", "hysteria2":
			if user.Password == "" {
				sl.ReportError(user.Password, "password", "Password", "required", "")
			}
		case "tuic":
			if user.UUID == "" {
				sl.ReportError(user.UUID, "uuid", "UUID", "required", "")
			}
			if user.Password == "" {
				sl.ReportError(user.Password, "password", "Password", "required", "")
			}
		case "ssh":
			if user.Password == "" && len(user.AuthorizedKeys) == 0 {
				sl.ReportError(user.Password, "password", "Password", "required_without", "")
			}
		case "mtproxy":
			if user.Secret == "" {
				sl.ReportError(user.Secret, "secret", "Secret", "required", "")
			}
		}
	}, constant.UserCreate{})
	validateRateLimiterInterval := func(sl validator.StructLevel, interval string) {
		if interval == "" {
			return
		}
		if _, err := time.ParseDuration(interval); err != nil {
			sl.ReportError(interval, "interval", "Interval", "duration", "")
		}
	}
	defaultValidator.RegisterStructValidation(func(sl validator.StructLevel) {
		validateRateLimiterInterval(sl, sl.Current().Interface().(constant.RateLimiterCreate).Interval)
	}, constant.RateLimiterCreate{})
	defaultValidator.RegisterStructValidation(func(sl validator.StructLevel) {
		validateRateLimiterInterval(sl, sl.Current().Interface().(constant.RateLimiterUpdate).Interval)
	}, constant.RateLimiterUpdate{})
	broadcastQueue := make(wpconstant.Queue)
	broadcastWorkers := make([]wpconstant.WorkerFactory, 16)
	for i := range broadcastWorkers {
		broadcastWorkers[i] = worker.NewWorkerFactory(broadcastQueue)
	}
	broadcastPool := pool.NewPool(broadcastWorkers)
	broadcastPool.Start()
	service := &Service{
		Adapter:          boxService.NewAdapter(C.TypeManager, tag),
		ctx:              ctx,
		logger:           logger,
		repository:       repository,
		nodes:            make(map[string]constant.ConnectedNode, 0),
		limiterLocks:     make(map[int]map[string]*cache.Cache[string, struct{}]),
		trafficUsage:     make(map[int]*TrafficUsage),
		defaultValidator: defaultValidator,
		broadcastQueue:   broadcastQueue,
		broadcastPool:    broadcastPool,
	}
	limiters, err := service.repository.GetTrafficLimiters(map[string][]string{})
	if err != nil {
		return nil, err
	}
	for _, limiter := range limiters {
		service.trafficUsage[limiter.ID] = &TrafficUsage{
			used:  limiter.RawUsed,
			quota: limiter.RawQuota,
		}
	}
	return service, nil
}

func (s *Service) CreateSquad(node constant.SquadCreate) (constant.Squad, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	err := s.defaultValidator.Struct(node)
	if err != nil {
		return constant.Squad{}, err
	}
	createdSquad, err := s.repository.CreateSquad(node)
	if err != nil {
		return createdSquad, err
	}
	return createdSquad, nil
}

func (s *Service) GetSquads(filters map[string][]string) ([]constant.Squad, error) {
	return s.repository.GetSquads(filters)
}

func (s *Service) GetSquadsCount(filters map[string][]string) (int, error) {
	return s.repository.GetSquadsCount(filters)
}

func (s *Service) GetSquad(id int) (constant.Squad, error) {
	return s.repository.GetSquad(id)
}

func (s *Service) UpdateSquad(id int, squad constant.SquadUpdate) (constant.Squad, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	err := s.defaultValidator.Struct(squad)
	if err != nil {
		return constant.Squad{}, err
	}
	updatedSquad, err := s.repository.UpdateSquad(id, squad)
	if err != nil {
		return updatedSquad, err
	}
	return updatedSquad, nil
}

func (s *Service) DeleteSquad(id int) (constant.Squad, error) {
	s.mtx.Lock()
	s.trafficMtx.Lock()
	s.connLockMtx.Lock()
	defer s.mtx.Unlock()
	defer s.trafficMtx.Unlock()
	defer s.connLockMtx.Unlock()
	deleted, err := s.repository.DeleteSquad(id)
	if err != nil {
		return deleted.Squad, err
	}
	for _, uuid := range deleted.OrphanedNodeUUIDs {
		if connectedNode, ok := s.nodes[uuid]; ok {
			connectedNode.Close()
			delete(s.nodes, uuid)
		}
	}
	for _, lid := range deleted.OrphanedTrafficLimiterIDs {
		delete(s.trafficUsage, lid)
	}
	for _, lid := range deleted.OrphanedConnectionLimiterIDs {
		delete(s.limiterLocks, lid)
	}
	for _, uuid := range deleted.SurvivingNodeUUIDs {
		connectedNode, ok := s.nodes[uuid]
		if !ok {
			continue
		}
		node, err := s.repository.GetNode(uuid)
		if err != nil {
			s.closeAllNodes()
			return deleted.Squad, err
		}
		squadIDs := convertIntSliceToStringSlice(node.SquadIDs)
		users, err := s.repository.GetUsers(map[string][]string{"squad_id_in": squadIDs})
		if err != nil {
			s.closeAllNodes()
			return deleted.Squad, err
		}
		connectedNode.UpdateUsers(users)
		bandwidthLimiters, err := s.repository.GetBandwidthLimiters(map[string][]string{"squad_id_in": squadIDs})
		if err != nil {
			s.closeAllNodes()
			return deleted.Squad, err
		}
		connectedNode.UpdateBandwidthLimiters(bandwidthLimiters)
		trafficLimiters, err := s.repository.GetTrafficLimiters(map[string][]string{"squad_id_in": squadIDs})
		if err != nil {
			s.closeAllNodes()
			return deleted.Squad, err
		}
		connectedNode.UpdateTrafficLimiters(trafficLimiters)
		connectionLimiters, err := s.repository.GetConnectionLimiters(map[string][]string{"squad_id_in": squadIDs})
		if err != nil {
			s.closeAllNodes()
			return deleted.Squad, err
		}
		connectedNode.UpdateConnectionLimiters(connectionLimiters)
		rateLimiters, err := s.repository.GetRateLimiters(map[string][]string{"squad_id_in": squadIDs})
		if err != nil {
			s.closeAllNodes()
			return deleted.Squad, err
		}
		connectedNode.UpdateRateLimiters(rateLimiters)
	}
	return deleted.Squad, nil
}

func (s *Service) CreateNode(node constant.NodeCreate) (constant.Node, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	err := s.defaultValidator.Struct(node)
	if err != nil {
		return constant.Node{}, err
	}
	createdNode, err := s.repository.CreateNode(node)
	if err != nil {
		return createdNode, err
	}
	return createdNode, nil
}

func (s *Service) GetNodes(filters map[string][]string) ([]constant.Node, error) {
	return s.repository.GetNodes(filters)
}

func (s *Service) GetNodesCount(filters map[string][]string) (int, error) {
	return s.repository.GetNodesCount(filters)
}

func (s *Service) GetNode(uuid string) (constant.Node, error) {
	return s.repository.GetNode(uuid)
}

func (s *Service) GetNodeStatus(uuid string) (string, error) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	node, ok := s.nodes[uuid]
	if !ok || !node.IsOnline() {
		return "offline", nil
	}
	return "online", nil
}

func (s *Service) UpdateNode(uuid string, node constant.NodeUpdate) (constant.Node, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	err := s.defaultValidator.Struct(node)
	if err != nil {
		return constant.Node{}, err
	}
	updatedNode, err := s.repository.UpdateNode(uuid, node)
	if err != nil {
		return updatedNode, err
	}
	return updatedNode, nil
}

func (s *Service) DeleteNode(uuid string) (constant.Node, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	deletedNode, err := s.repository.DeleteNode(uuid)
	if err != nil {
		return deletedNode, err
	}
	node, ok := s.nodes[uuid]
	if ok {
		node.Close()
		delete(s.nodes, uuid)
	}
	return deletedNode, nil
}

func (s *Service) CreateUser(user constant.UserCreate) (constant.User, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	err := s.defaultValidator.Struct(user)
	if err != nil {
		return constant.User{}, err
	}
	createdUser, err := s.repository.CreateUser(user)
	if err != nil {
		return createdUser, err
	}
	nodes, err := s.repository.GetNodes(map[string][]string{
		"squad_id_in": convertIntSliceToStringSlice(createdUser.SquadIDs),
	})
	if err != nil {
		s.closeAllNodes()
		return createdUser, err
	}
	s.dispatchToNodes(nodes, func(node constant.ConnectedNode) {
		node.UpdateUser(createdUser)
	})
	return createdUser, nil
}

func (s *Service) GetUsers(filters map[string][]string) ([]constant.User, error) {
	return s.repository.GetUsers(filters)
}

func (s *Service) GetUsersCount(filters map[string][]string) (int, error) {
	return s.repository.GetUsersCount(filters)
}

func (s *Service) GetUser(id int) (constant.User, error) {
	return s.repository.GetUser(id)
}

func (s *Service) UpdateUser(id int, user constant.UserUpdate) (constant.User, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	err := s.defaultValidator.Struct(user)
	if err != nil {
		return constant.User{}, err
	}
	updatedUser, err := s.repository.UpdateUser(id, user)
	if err != nil {
		return updatedUser, err
	}
	nodes, err := s.repository.GetNodes(map[string][]string{
		"squad_id_in": convertIntSliceToStringSlice(updatedUser.SquadIDs),
	})
	if err != nil {
		s.closeAllNodes()
		return updatedUser, err
	}
	s.dispatchToNodes(nodes, func(node constant.ConnectedNode) {
		node.UpdateUser(updatedUser)
	})
	return updatedUser, nil
}

func (s *Service) DeleteUser(id int) (constant.User, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	deletedUser, err := s.repository.DeleteUser(id)
	if err != nil {
		return deletedUser, err
	}
	nodes, err := s.repository.GetNodes(map[string][]string{
		"squad_id_in": convertIntSliceToStringSlice(deletedUser.SquadIDs),
	})
	if err != nil {
		s.closeAllNodes()
		return deletedUser, err
	}
	s.dispatchToNodes(nodes, func(node constant.ConnectedNode) {
		node.DeleteUser(deletedUser)
	})
	return deletedUser, nil
}

func (s *Service) CreateBandwidthLimiter(limiter constant.BandwidthLimiterCreate) (constant.BandwidthLimiter, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	err := s.defaultValidator.Struct(limiter)
	if err != nil {
		return constant.BandwidthLimiter{}, err
	}
	createdLimiter, err := s.repository.CreateBandwidthLimiter(limiter)
	if err != nil {
		return createdLimiter, err
	}
	nodes, err := s.repository.GetNodes(map[string][]string{
		"squad_id_in": convertIntSliceToStringSlice(createdLimiter.SquadIDs),
	})
	if err != nil {
		s.closeAllNodes()
		return createdLimiter, err
	}
	s.dispatchToNodes(nodes, func(node constant.ConnectedNode) {
		node.UpdateBandwidthLimiter(createdLimiter)
	})
	return createdLimiter, nil
}

func (s *Service) GetBandwidthLimiters(filters map[string][]string) ([]constant.BandwidthLimiter, error) {
	return s.repository.GetBandwidthLimiters(filters)
}

func (s *Service) GetBandwidthLimitersCount(filters map[string][]string) (int, error) {
	return s.repository.GetBandwidthLimitersCount(filters)
}

func (s *Service) GetBandwidthLimiter(id int) (constant.BandwidthLimiter, error) {
	return s.repository.GetBandwidthLimiter(id)
}

func (s *Service) UpdateBandwidthLimiter(id int, limiter constant.BandwidthLimiterUpdate) (constant.BandwidthLimiter, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	err := s.defaultValidator.Struct(limiter)
	if err != nil {
		return constant.BandwidthLimiter{}, err
	}
	updatedLimiter, err := s.repository.UpdateBandwidthLimiter(id, limiter)
	if err != nil {
		return updatedLimiter, err
	}
	nodes, err := s.repository.GetNodes(map[string][]string{
		"squad_id_in": convertIntSliceToStringSlice(updatedLimiter.SquadIDs),
	})
	if err != nil {
		s.closeAllNodes()
		return updatedLimiter, err
	}
	s.dispatchToNodes(nodes, func(node constant.ConnectedNode) {
		node.UpdateBandwidthLimiter(updatedLimiter)
	})
	return updatedLimiter, nil
}

func (s *Service) DeleteBandwidthLimiter(id int) (constant.BandwidthLimiter, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	deletedLimiter, err := s.repository.DeleteBandwidthLimiter(id)
	if err != nil {
		return deletedLimiter, err
	}
	nodes, err := s.repository.GetNodes(map[string][]string{
		"squad_id_in": convertIntSliceToStringSlice(deletedLimiter.SquadIDs),
	})
	if err != nil {
		s.closeAllNodes()
		return deletedLimiter, err
	}
	s.dispatchToNodes(nodes, func(node constant.ConnectedNode) {
		node.DeleteBandwidthLimiter(deletedLimiter)
	})
	return deletedLimiter, nil
}

func (s *Service) CreateTrafficLimiter(limiter constant.TrafficLimiterCreate) (constant.TrafficLimiter, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	err := s.defaultValidator.Struct(limiter)
	if err != nil {
		return constant.TrafficLimiter{}, err
	}
	createdLimiter, err := s.repository.CreateTrafficLimiter(limiter)
	if err != nil {
		return createdLimiter, err
	}
	s.trafficMtx.Lock()
	s.trafficUsage[createdLimiter.ID] = &TrafficUsage{
		used:  createdLimiter.RawUsed,
		quota: createdLimiter.RawQuota,
	}
	s.trafficMtx.Unlock()
	nodes, err := s.repository.GetNodes(map[string][]string{
		"squad_id_in": convertIntSliceToStringSlice(createdLimiter.SquadIDs),
	})
	if err != nil {
		s.closeAllNodes()
		return createdLimiter, err
	}
	s.dispatchToNodes(nodes, func(node constant.ConnectedNode) {
		node.UpdateTrafficLimiter(createdLimiter)
	})
	return createdLimiter, nil
}

func (s *Service) GetTrafficLimiters(filters map[string][]string) ([]constant.TrafficLimiter, error) {
	return s.repository.GetTrafficLimiters(filters)
}

func (s *Service) GetTrafficLimitersCount(filters map[string][]string) (int, error) {
	return s.repository.GetTrafficLimitersCount(filters)
}

func (s *Service) GetTrafficLimiter(id int) (constant.TrafficLimiter, error) {
	return s.repository.GetTrafficLimiter(id)
}

func (s *Service) UpdateTrafficLimiter(id int, limiter constant.TrafficLimiterUpdate) (constant.TrafficLimiter, error) {
	s.mtx.Lock()
	s.trafficMtx.Lock()
	defer s.mtx.Unlock()
	defer s.trafficMtx.Unlock()
	err := s.defaultValidator.Struct(limiter)
	if err != nil {
		return constant.TrafficLimiter{}, err
	}
	updatedLimiter, err := s.repository.UpdateTrafficLimiter(id, limiter)
	if err != nil {
		return updatedLimiter, err
	}
	s.trafficUsage[updatedLimiter.ID] = &TrafficUsage{
		used:  updatedLimiter.RawUsed,
		quota: updatedLimiter.RawQuota,
	}
	nodes, err := s.repository.GetNodes(map[string][]string{
		"squad_id_in": convertIntSliceToStringSlice(updatedLimiter.SquadIDs),
	})
	if err != nil {
		s.closeAllNodes()
		return updatedLimiter, err
	}
	s.dispatchToNodes(nodes, func(node constant.ConnectedNode) {
		node.UpdateTrafficLimiter(updatedLimiter)
	})
	return updatedLimiter, nil
}

func (s *Service) UpdateTrafficLimiterUsed(id int, used uint64) (constant.TrafficLimiter, error) {
	s.mtx.Lock()
	s.trafficMtx.Lock()
	defer s.mtx.Unlock()
	defer s.trafficMtx.Unlock()
	updatedLimiter, err := s.repository.UpdateTrafficLimiterUsed(id, used)
	if err != nil {
		return updatedLimiter, err
	}
	s.trafficUsage[updatedLimiter.ID] = &TrafficUsage{
		used:  updatedLimiter.RawUsed,
		quota: updatedLimiter.RawQuota,
	}
	nodes, err := s.repository.GetNodes(map[string][]string{
		"squad_id_in": convertIntSliceToStringSlice(updatedLimiter.SquadIDs),
	})
	if err != nil {
		s.closeAllNodes()
		return updatedLimiter, err
	}
	s.dispatchToNodes(nodes, func(node constant.ConnectedNode) {
		node.UpdateTrafficLimiter(updatedLimiter)
	})
	return updatedLimiter, nil
}

func (s *Service) DeleteTrafficLimiter(id int) (constant.TrafficLimiter, error) {
	s.mtx.Lock()
	s.trafficMtx.Lock()
	defer s.mtx.Unlock()
	defer s.trafficMtx.Unlock()
	deletedLimiter, err := s.repository.DeleteTrafficLimiter(id)
	if err != nil {
		return deletedLimiter, err
	}
	delete(s.trafficUsage, deletedLimiter.ID)
	nodes, err := s.repository.GetNodes(map[string][]string{
		"squad_id_in": convertIntSliceToStringSlice(deletedLimiter.SquadIDs),
	})
	if err != nil {
		s.closeAllNodes()
		return deletedLimiter, err
	}
	s.dispatchToNodes(nodes, func(node constant.ConnectedNode) {
		node.DeleteTrafficLimiter(deletedLimiter)
	})
	return deletedLimiter, nil
}

func (s *Service) CreateConnectionLimiter(limiter constant.ConnectionLimiterCreate) (constant.ConnectionLimiter, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	err := s.defaultValidator.Struct(limiter)
	if err != nil {
		return constant.ConnectionLimiter{}, err
	}
	createdLimiter, err := s.repository.CreateConnectionLimiter(limiter)
	if err != nil {
		return createdLimiter, err
	}
	nodes, err := s.repository.GetNodes(map[string][]string{
		"squad_id_in": convertIntSliceToStringSlice(createdLimiter.SquadIDs),
	})
	if err != nil {
		s.closeAllNodes()
		return createdLimiter, err
	}
	s.dispatchToNodes(nodes, func(node constant.ConnectedNode) {
		node.UpdateConnectionLimiter(createdLimiter)
	})
	return createdLimiter, nil
}

func (s *Service) GetConnectionLimiters(filters map[string][]string) ([]constant.ConnectionLimiter, error) {
	return s.repository.GetConnectionLimiters(filters)
}

func (s *Service) GetConnectionLimitersCount(filters map[string][]string) (int, error) {
	return s.repository.GetConnectionLimitersCount(filters)
}

func (s *Service) GetConnectionLimiter(id int) (constant.ConnectionLimiter, error) {
	return s.repository.GetConnectionLimiter(id)
}

func (s *Service) UpdateConnectionLimiter(id int, limiter constant.ConnectionLimiterUpdate) (constant.ConnectionLimiter, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	err := s.defaultValidator.Struct(limiter)
	if err != nil {
		return constant.ConnectionLimiter{}, err
	}
	updatedLimiter, err := s.repository.UpdateConnectionLimiter(id, limiter)
	if err != nil {
		return updatedLimiter, err
	}
	nodes, err := s.repository.GetNodes(map[string][]string{
		"squad_id_in": convertIntSliceToStringSlice(updatedLimiter.SquadIDs),
	})
	if err != nil {
		s.closeAllNodes()
		return updatedLimiter, err
	}
	s.dispatchToNodes(nodes, func(node constant.ConnectedNode) {
		node.UpdateConnectionLimiter(updatedLimiter)
	})
	if limiter.LockType != "manager" {
		s.connLockMtx.Lock()
		defer s.connLockMtx.Unlock()
		delete(s.limiterLocks, id)
	}
	return updatedLimiter, nil
}

func (s *Service) DeleteConnectionLimiter(id int) (constant.ConnectionLimiter, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	deletedLimiter, err := s.repository.DeleteConnectionLimiter(id)
	if err != nil {
		return deletedLimiter, err
	}
	nodes, err := s.repository.GetNodes(map[string][]string{
		"squad_id_in": convertIntSliceToStringSlice(deletedLimiter.SquadIDs),
	})
	if err != nil {
		s.closeAllNodes()
		return deletedLimiter, err
	}
	s.dispatchToNodes(nodes, func(node constant.ConnectedNode) {
		node.DeleteConnectionLimiter(deletedLimiter)
	})
	if deletedLimiter.LockType == "manager" {
		s.connLockMtx.Lock()
		defer s.connLockMtx.Unlock()
		delete(s.limiterLocks, id)
	}
	return deletedLimiter, nil
}

func (s *Service) CreateRateLimiter(limiter constant.RateLimiterCreate) (constant.RateLimiter, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	err := s.defaultValidator.Struct(limiter)
	if err != nil {
		return constant.RateLimiter{}, err
	}
	createdLimiter, err := s.repository.CreateRateLimiter(limiter)
	if err != nil {
		return createdLimiter, err
	}
	nodes, err := s.repository.GetNodes(map[string][]string{
		"squad_id_in": convertIntSliceToStringSlice(createdLimiter.SquadIDs),
	})
	if err != nil {
		s.closeAllNodes()
		return createdLimiter, err
	}
	s.dispatchToNodes(nodes, func(node constant.ConnectedNode) {
		node.UpdateRateLimiter(createdLimiter)
	})
	return createdLimiter, nil
}

func (s *Service) GetRateLimiters(filters map[string][]string) ([]constant.RateLimiter, error) {
	return s.repository.GetRateLimiters(filters)
}

func (s *Service) GetRateLimitersCount(filters map[string][]string) (int, error) {
	return s.repository.GetRateLimitersCount(filters)
}

func (s *Service) GetRateLimiter(id int) (constant.RateLimiter, error) {
	return s.repository.GetRateLimiter(id)
}

func (s *Service) UpdateRateLimiter(id int, limiter constant.RateLimiterUpdate) (constant.RateLimiter, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	err := s.defaultValidator.Struct(limiter)
	if err != nil {
		return constant.RateLimiter{}, err
	}
	updatedLimiter, err := s.repository.UpdateRateLimiter(id, limiter)
	if err != nil {
		return updatedLimiter, err
	}
	nodes, err := s.repository.GetNodes(map[string][]string{
		"squad_id_in": convertIntSliceToStringSlice(updatedLimiter.SquadIDs),
	})
	if err != nil {
		s.closeAllNodes()
		return updatedLimiter, err
	}
	s.dispatchToNodes(nodes, func(node constant.ConnectedNode) {
		node.UpdateRateLimiter(updatedLimiter)
	})
	return updatedLimiter, nil
}

func (s *Service) DeleteRateLimiter(id int) (constant.RateLimiter, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	deletedLimiter, err := s.repository.DeleteRateLimiter(id)
	if err != nil {
		return deletedLimiter, err
	}
	nodes, err := s.repository.GetNodes(map[string][]string{
		"squad_id_in": convertIntSliceToStringSlice(deletedLimiter.SquadIDs),
	})
	if err != nil {
		s.closeAllNodes()
		return deletedLimiter, err
	}
	s.dispatchToNodes(nodes, func(node constant.ConnectedNode) {
		node.DeleteRateLimiter(deletedLimiter)
	})
	return deletedLimiter, nil
}

func (s *Service) AddNode(uuid string, node constant.ConnectedNode) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	var node_ constant.Node
	var err error
	node_, err = s.repository.GetNode(uuid)
	if err != nil {
		return err
	}
	squadIDs := convertIntSliceToStringSlice(node_.SquadIDs)
	users, err := s.repository.GetUsers(map[string][]string{
		"squad_id_in": squadIDs,
	})
	if err != nil {
		return err
	}
	node.UpdateUsers(users)
	bandwidthLimiters, err := s.repository.GetBandwidthLimiters(map[string][]string{
		"squad_id_in": squadIDs,
	})
	if err != nil {
		return err
	}
	node.UpdateBandwidthLimiters(bandwidthLimiters)
	trafficLimiters, err := s.repository.GetTrafficLimiters(map[string][]string{
		"squad_id_in": squadIDs,
	})
	if err != nil {
		return err
	}
	node.UpdateTrafficLimiters(trafficLimiters)
	connectionLimiters, err := s.repository.GetConnectionLimiters(map[string][]string{
		"squad_id_in": squadIDs,
	})
	if err != nil {
		return err
	}
	node.UpdateConnectionLimiters(connectionLimiters)
	rateLimiters, err := s.repository.GetRateLimiters(map[string][]string{
		"squad_id_in": squadIDs,
	})
	if err != nil {
		return err
	}
	node.UpdateRateLimiters(rateLimiters)
	s.nodes[uuid] = node
	return nil
}

func (s *Service) AcquireLock(limiterId int, id string) (string, error) {
	s.connLockMtx.Lock()
	defer s.connLockMtx.Unlock()
	limiter, err := s.repository.GetConnectionLimiter(limiterId)
	if err != nil {
		return "", err
	}
	if limiter.LockType != "manager" {
		return "", E.New("invalid lock type")
	}
	locks, ok := s.limiterLocks[limiterId]
	if !ok {
		locks = make(map[string]*cache.Cache[string, struct{}])
		s.limiterLocks[limiter.ID] = locks
	}
	lock, ok := locks[id]
	if !ok {
		if len(locks) == int(limiter.Count) {
			return "", E.New("not enough free locks")
		}
		lock = cache.New[string, struct{}](time.Second*30, time.Second)
		lock.OnEvicted(func(_ string, _ struct{}) {
			s.connLockMtx.Lock()
			defer s.connLockMtx.Unlock()
			if lock.ItemCount() == 0 {
				delete(locks, id)
			}
		})
		locks[id] = lock
	}
	handleID, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	lock.SetDefault(handleID.String(), struct{}{})
	return handleID.String(), nil
}

func (s *Service) RefreshLock(limiterId int, id string, handleId string) error {
	s.connLockMtx.Lock()
	defer s.connLockMtx.Unlock()
	locks, ok := s.limiterLocks[limiterId]
	if !ok {
		return E.New("limiter not found")
	}
	lock, ok := locks[id]
	if !ok {
		return E.New("lock not found")
	}
	err := lock.Replace(handleId, struct{}{}, time.Second*30)
	return err
}

func (s *Service) ReleaseLock(limiterId int, id string, handleId string) error {
	s.connLockMtx.Lock()
	defer s.connLockMtx.Unlock()
	locks, ok := s.limiterLocks[limiterId]
	if !ok {
		return E.New("limiter not found")
	}
	lock, ok := locks[id]
	if !ok {
		return E.New("lock not found")
	}
	go lock.Delete(handleId)
	return nil
}

func (s *Service) AddTrafficUsage(limiterId int, n uint64) (uint64, error) {
	s.trafficMtx.Lock()
	defer s.trafficMtx.Unlock()
	trafficStat, ok := s.trafficUsage[limiterId]
	if !ok {
		return 0, E.New("limiter not found")
	}
	trafficStat.used = trafficStat.used + n
	if trafficStat.used > trafficStat.quota {
		trafficStat.used = trafficStat.quota
	}
	updatedLimiter, err := s.repository.UpdateTrafficLimiterUsed(limiterId, trafficStat.used)
	if err != nil {
		return 0, err
	}
	trafficStat.used = updatedLimiter.RawUsed
	return trafficStat.used, nil
}

func (s *Service) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	scope.Add(func() error {
		s.broadcastPool.Stop()
		return nil
	})
	return nil
}

type TrafficUsage struct {
	used  uint64
	quota uint64
}

func (s *Service) closeAllNodes() {
	for _, node := range s.nodes {
		node.Close()
	}
}

func (s *Service) dispatchToNodes(nodes []constant.Node, fn func(node constant.ConnectedNode)) {
	awaits := make([]<-chan struct{}, 0, len(nodes))
	for _, node := range nodes {
		connectedNode, ok := s.nodes[node.UUID]
		if !ok {
			continue
		}
		awaits = append(awaits, tools.Await(s.broadcastQueue, func() {
			fn(connectedNode)
		}))
	}
	for _, await := range awaits {
		<-await
	}
}

func convertIntSliceToStringSlice(values []int) []string {
	result := make([]string, len(values))
	for i, v := range values {
		result[i] = strconv.Itoa(v)
	}
	return result
}

// Package smart_dns_pool provides a sing-box service that runs a local DNS
// server fronting many recursive upstream resolvers, using
// github.com/hiddify/hmrd_multi_resolver_dns under the hood.
//
// Why: dnstt's tunnel sends DNS queries to a single recursive resolver
// (e.g. `8.8.8.8`). When that resolver gets rate-limited or blocked the
// tunnel stalls. Configure this service with the recursive resolvers you
// want to distribute load across, then point dnstt's `resolvers` at the
// service's listen address (e.g. `udp://127.0.0.1:19876`). dnstt sees a
// normal local resolver; the service transparently fans queries out to
// many real upstreams with deadline-aware failover, AIMD rate-limit
// throttling, and recovery probing.
package smart_dns_pool

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	multidns "github.com/hiddify/hmrd_multi_resolver_dns"
)

// RegisterService hooks the smart_dns_pool service type into the registry.
func RegisterService(registry *boxService.Registry) {
	boxService.Register[option.SmartDNSPoolServiceOptions](registry, C.TypeSmartDNSPool, NewService)
}

var _ adapter.Service = (*Service)(nil)

type Service struct {
	boxService.Adapter
	logger log.ContextLogger
	opts   option.SmartDNSPoolServiceOptions

	listenAddr string

	mu         sync.Mutex
	mgr        *multidns.Manager
	server     *multidns.Server
	serverOnce sync.Once
	serveErr   chan error
}

// NewService constructs a smart_dns_pool service. It validates the options
// up-front so config errors surface at parse time, but defers any network
// activity (binding the listener, building upstream transports) to Start.
func NewService(ctx context.Context, logger log.ContextLogger, tag string, opts option.SmartDNSPoolServiceOptions) (adapter.Service, error) {
	if len(opts.Upstreams) == 0 {
		return nil, E.New("smart_dns_pool: at least one upstream is required")
	}

	host := "127.0.0.1"
	if opts.Listen != nil {
		host = opts.Listen.Build(netip.AddrFrom4([4]byte{127, 0, 0, 1})).String()
	}
	port := opts.ListenPort
	if port == 0 {
		return nil, E.New("smart_dns_pool: listen_port is required (e.g. 19876)")
	}

	for i, up := range opts.Upstreams {
		if up.Address == "" {
			return nil, E.New("smart_dns_pool: upstream #", i, " missing address")
		}
		if _, err := protocolFromString(up.Type); err != nil {
			return nil, E.Cause(err, "smart_dns_pool: upstream #", i)
		}
	}

	return &Service{
		Adapter:    boxService.NewAdapter(C.TypeSmartDNSPool, tag),
		logger:     logger,
		opts:       opts,
		listenAddr: net.JoinHostPort(host, strconv.Itoa(int(port))),
	}, nil
}

// Start brings up the smart pool and binds the local DNS listener. It runs
// at the StartStart stage so dnstt outbounds (which start later) find a
// listener already accepting queries on their first request.
func (s *Service) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	mgr := multidns.New(multidns.Options{
		DefaultDeadline:        time.Duration(s.opts.Deadline),
		DefaultResolverTimeout: time.Duration(s.opts.PerAttempt),
		ProbeInterval:          time.Duration(s.opts.ProbeInterval),
		DownAfterFailures:      s.opts.DownAfter,
		LoadBalance:            lbFromString(s.opts.LoadBalance),
		Logger:                 newLoggerAdapter(s.logger, s.Tag()),
	})

	for i, up := range s.opts.Upstreams {
		proto, _ := protocolFromString(up.Type) // already validated in NewService
		cfg := multidns.ResolverConfig{
			Name:     up.Name,
			Protocol: proto,
			Address:  up.Address,
			Weight:   up.Weight,
		}
		if _, err := mgr.AddResolver(cfg); err != nil {
			_ = mgr.Close()
			return E.Cause(err, "smart_dns_pool: register upstream #", i, " (", up.Type, " ", up.Address, ")")
		}
	}

	srv := mgr.NewServer(s.listenAddr) // UDP+TCP by default
	s.serveErr = make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			s.serveErr <- err
			s.logger.Error("smart_dns_pool: listener exited: ", err)
		}
	}()

	s.mgr = mgr
	s.server = srv
	s.logger.Info("smart_dns_pool: listening on ", s.listenAddr, " (udp+tcp), ", len(s.opts.Upstreams), " upstream(s)")
	return nil
}

func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var firstErr error
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := s.server.Shutdown(ctx); err != nil {
			firstErr = err
		}
		cancel()
		s.server = nil
	}
	if s.mgr != nil {
		if err := s.mgr.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.mgr = nil
	}
	return firstErr
}

func protocolFromString(s string) (multidns.Protocol, error) {
	switch s {
	case "udp", "":
		return multidns.ProtoUDP, nil
	case "tcp":
		return multidns.ProtoTCP, nil
	case "tls", "dot":
		return multidns.ProtoDoT, nil
	case "https", "doh":
		return multidns.ProtoDoH, nil
	default:
		return "", fmt.Errorf("unsupported upstream type %q (want udp|tcp|tls|https)", s)
	}
}

func lbFromString(s string) multidns.LBStrategy {
	switch s {
	case "weighted":
		return multidns.LBWeighted
	case "lowest_latency":
		return multidns.LBLowestLatency
	default:
		return multidns.LBRoundRobin
	}
}

// loggerAdapter bridges sing-box's ContextLogger to multidns.Logger
// (printf-style). The tag prefix lets operators tell which service
// instance produced a line when multiple smart_dns_pool services are
// configured.
type loggerAdapter struct {
	logger log.ContextLogger
	tag    string
}

func newLoggerAdapter(logger log.ContextLogger, tag string) *loggerAdapter {
	return &loggerAdapter{logger: logger, tag: tag}
}

func (l *loggerAdapter) Debugf(format string, args ...any) {
	l.logger.Debug(l.tag, ": ", fmt.Sprintf(format, args...))
}
func (l *loggerAdapter) Infof(format string, args ...any) {
	l.logger.Info(l.tag, ": ", fmt.Sprintf(format, args...))
}
func (l *loggerAdapter) Warnf(format string, args ...any) {
	l.logger.Warn(l.tag, ": ", fmt.Sprintf(format, args...))
}
func (l *loggerAdapter) Errorf(format string, args ...any) {
	l.logger.Error(l.tag, ": ", fmt.Sprintf(format, args...))
}

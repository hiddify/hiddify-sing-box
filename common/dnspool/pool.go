package dnspool

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	multidns "github.com/hiddify/hmrd_multi_resolver_dns"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// PoolOptions tune a resolver pool, from an outbound's smart_pool block. Zero values take the
// pool's defaults: a 5 s deadline, 2 s per try (less once a resolver's latency is known), a 5 s
// probe interval, down after 8 failures, auto load balancing.
type PoolOptions struct {
	LoadBalance   string // roundrobin, weighted or lowest_latency
	Deadline      time.Duration
	PerAttempt    time.Duration
	ProbeInterval time.Duration
	DownAfter     int
	Duplicate     int // resolvers each query is sent to, copies included (see multidns.Options)
	// FailFast answers a query that finds every resolver at its rate cap with SERVFAIL at once
	// instead of holding it up to 300 ms for a token (multidns.Options.PacingMaxWait). For a
	// tunnel whose client times its own retransmissions by the round trip (DNSTT's KCP) a held
	// query inflates the round trip and shrinks its window; a failed one is retransmitted.
	FailFast bool
}

// PoolOptionsFrom reads an outbound's smart_pool block; nil means the defaults.
func PoolOptionsFrom(options *option.SmartPoolOptions) PoolOptions {
	if options == nil {
		return PoolOptions{}
	}
	return PoolOptions{
		LoadBalance:   options.LoadBalance,
		Deadline:      time.Duration(options.Deadline),
		PerAttempt:    time.Duration(options.PerAttempt),
		ProbeInterval: time.Duration(options.ProbeInterval),
		DownAfter:     options.DownAfter,
		Duplicate:     options.Duplicate,
	}
}

func managerOptions(logger log.ContextLogger, tag string, options PoolOptions) multidns.Options {
	return multidns.Options{
		DefaultDeadline:        options.Deadline,
		DefaultResolverTimeout: options.PerAttempt,
		ProbeInterval:          options.ProbeInterval,
		DownAfterFailures:      options.DownAfter,
		LoadBalance:            LBFromString(options.LoadBalance),
		PacingMaxWait:          pacingMaxWait(options.FailFast),
		Logger:                 NewLoggerAdapter(logger, tag),
	}
}

// pacingMaxWait is multidns' wait for capacity: its default, or none.
func pacingMaxWait(failFast bool) time.Duration {
	if failFast {
		return -1
	}
	return 0
}

// DialFunc returns the dial function the pool's resolver sockets use: a
// sing-box default dialer with the outbound's dialer options, so
// bind_interface, routing_mark and the platform's socket protection apply
// and, on a VPN, the queries do not loop back into the tunnel.
func DialFunc(ctx context.Context, dialerOptions option.DialerOptions) (multidns.DialFunc, error) {
	dialerOptions.Detour = ""
	d, err := dialer.NewDefault(ctx, dialerOptions)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return d.DialContext(ctx, network, M.ParseSocksaddr(address))
	}, nil
}

// Pool is an outbound's own resolver pool, with a local DNS listener on 127.0.0.1: the DNS
// tunnel points at Addr() as its one resolver, and the pool spreads the queries over the
// resolvers added to it, slows down for one that rate-limits and skips one that stops answering.
// Each outbound runs its own.
type Pool struct {
	manager *multidns.Manager
	addr    string
	dial    multidns.DialFunc
}

// StartPool starts a pool listening on a free local port. It is bound when this returns. dial,
// when set, opens every resolver socket (see DialFunc).
func StartPool(logger log.ContextLogger, tag string, options PoolOptions, dial multidns.DialFunc) (*Pool, error) {
	manager, addr, err := multidns.StartLocal(managerOptions(logger, tag, options))
	if err != nil {
		return nil, E.Cause(err, "start resolver pool")
	}
	return &Pool{manager: manager, addr: addr, dial: dial}, nil
}

// Addr is the local "127.0.0.1:port" the tunnel sends its queries to.
func (p *Pool) Addr() string {
	return p.addr
}

// Add puts a resolver in the pool: "1.1.1.1:53" or "1.1.1.1" (UDP), "udp://", "tcp://",
// "dot://host:853" or "https://host/dns-query".
func (p *Pool) Add(resolver string) error {
	config, err := multidns.ParseResolverURL(resolver)
	if err != nil {
		return err
	}
	config.Dialer = p.dial
	_, err = p.manager.AddResolver(config)
	return err
}

// Manager gives access to the pool's manager, for statistics.
func (p *Pool) Manager() *multidns.Manager {
	return p.manager
}

// Close stops the listener and the pool.
func (p *Pool) Close() error {
	if p == nil || p.manager == nil {
		return nil
	}
	return p.manager.Close()
}

// ValidateResolver checks that a resolver is written in a form the pool accepts: "host:port" or
// "host" (UDP), "udp://", "tcp://", "dot://host:853" or "https://host/dns-query".
func ValidateResolver(address string) error {
	config, err := multidns.ParseResolverURL(address)
	if err != nil {
		return err
	}
	if config.Protocol == multidns.ProtoDoH {
		return nil
	}
	host, _, err := net.SplitHostPort(config.Address)
	if err != nil {
		return E.Cause(err, "resolver ", address)
	}
	if host == "" || strings.ContainsAny(host, "/ ") {
		return E.New("resolver ", address, ": not a host or IP")
	}
	return nil
}

// ProtocolFromString reads an upstream type: udp (also ""), tcp, tls or dot, https or doh.
func ProtocolFromString(s string) (multidns.Protocol, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
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

// LBFromString reads a load balance strategy. Empty and unknown values mean auto: each query
// goes to the resolver with the most spare capacity, within the rate each one is learned to take.
func LBFromString(s string) multidns.LBStrategy {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "roundrobin", "round_robin", "round-robin":
		return multidns.LBRoundRobin
	case "weighted":
		return multidns.LBWeighted
	case "lowest_latency", "lowest-latency":
		return multidns.LBLowestLatency
	default:
		return multidns.LBAuto
	}
}

// LoggerAdapter bridges sing-box's logger to the pool's printf-style logger, with a tag prefix so
// the lines of each pool can be told apart.
type LoggerAdapter struct {
	logger log.ContextLogger
	tag    string
}

// NewLoggerAdapter returns the pool logger for a sing-box logger.
func NewLoggerAdapter(logger log.ContextLogger, tag string) *LoggerAdapter {
	return &LoggerAdapter{logger: logger, tag: tag}
}

func (l *LoggerAdapter) Debugf(format string, args ...any) {
	l.logger.Debug(l.tag, ": ", fmt.Sprintf(format, args...))
}

func (l *LoggerAdapter) Infof(format string, args ...any) {
	l.logger.Info(l.tag, ": ", fmt.Sprintf(format, args...))
}

func (l *LoggerAdapter) Warnf(format string, args ...any) {
	l.logger.Warn(l.tag, ": ", fmt.Sprintf(format, args...))
}

func (l *LoggerAdapter) Errorf(format string, args ...any) {
	l.logger.Error(l.tag, ": ", fmt.Sprintf(format, args...))
}

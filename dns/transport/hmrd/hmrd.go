// Package hmrd implements a sing-box DNS transport that delegates to the
// hmrd_multi_resolver_dns library, exposing a single DNS server tag fronting
// many upstream resolvers (UDP / TCP / DoT / DoH) with adaptive rate-limit
// throttling, deadline-aware failover, and recovery probing.
//
// The transport's DialerOptions (including any "detour" outbound) is wired
// into every upstream as a custom DialFunc, so all resolver traffic flows
// through the configured outbound — the library's main reason for existing.
package hmrd

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	multidns "github.com/hiddify/hmrd_multi_resolver_dns"
	mDNS "github.com/miekg/dns"
)

var _ adapter.DNSTransport = (*Transport)(nil)

// Register hooks the "hmrd" type into the sing-box DNS transport registry.
func Register(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.HMRDDNSServerOptions](registry, C.DNSTypeHMRD, New)
}

// Transport is the sing-box DNSTransport implementation; it owns a
// multidns.Manager and delegates Exchange to it.
type Transport struct {
	dns.TransportAdapter
	logger log.ContextLogger
	mgr    *multidns.Manager
	dialer N.Dialer
}

// New constructs an "hmrd" transport from sing-box options.
func New(ctx context.Context, logger log.ContextLogger, tag string, options option.HMRDDNSServerOptions) (adapter.DNSTransport, error) {
	if len(options.Upstreams) == 0 {
		return nil, E.New("hmrd: at least one upstream resolver is required")
	}

	// One sing-box dialer is built for the whole transport (carrying any
	// detour). It's applied uniformly to every upstream — when users want
	// different outbounds for different resolvers, they should configure
	// separate hmrd transports.
	transportDialer, err := dialer.New(ctx, options.DialerOptions, false)
	if err != nil {
		return nil, E.Cause(err, "hmrd: build dialer")
	}

	mgr := multidns.New(multidns.Options{
		DefaultDeadline:        time.Duration(options.Deadline),
		DefaultResolverTimeout: time.Duration(options.PerAttempt),
		ProbeInterval:          time.Duration(options.ProbeInterval),
		DownAfterFailures:      options.DownAfter,
		LoadBalance:            parseLBStrategy(options.LoadBalance),
		Logger:                 &singboxLogger{logger: logger, tag: tag},
	})

	dialFunc := newDialFuncFromSingbox(transportDialer)
	for i, up := range options.Upstreams {
		proto, err := parseProtocol(up.Type)
		if err != nil {
			_ = mgr.Close()
			return nil, E.Cause(err, "hmrd: upstream #", i)
		}
		if up.Address == "" {
			_ = mgr.Close()
			return nil, E.New("hmrd: upstream #", i, " missing address")
		}
		cfg := multidns.ResolverConfig{
			Name:     up.Name,
			Protocol: proto,
			Address:  up.Address,
			Weight:   up.Weight,
			Dialer:   dialFunc,
		}
		if _, err := mgr.AddResolver(cfg); err != nil {
			_ = mgr.Close()
			return nil, E.Cause(err, "hmrd: register upstream #", i, " (", up.Type, " ", up.Address, ")")
		}
	}

	return &Transport{
		TransportAdapter: dns.NewTransportAdapterWithLocalOptions(C.DNSTypeHMRD, tag, option.LocalDNSServerOptions{RawLocalDNSServerOptions: options.RawLocalDNSServerOptions}),
		logger:           logger,
		mgr:              mgr,
		dialer:           transportDialer,
	}, nil
}

// Start implements adapter.Lifecycle. It triggers detour resolution so the
// upstreams' DialFunc resolves to the right outbound on first use.
func (t *Transport) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return dialer.InitializeDetour(t.dialer)
}

// Close shuts down the multidns.Manager (cancelling probers, closing
// upstream connections).
func (t *Transport) Close() error {
	return t.mgr.Close()
}

// Reset is a no-op — multidns has no per-resolver pinned state to clear.
func (t *Transport) Reset() {}

// Exchange dispatches the query into the multidns pool. The Manager applies
// its own deadline-aware retry, AIMD throttling, and recovery probing.
func (t *Transport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	return t.mgr.Resolve(ctx, message)
}

// newDialFuncFromSingbox adapts a sing-box N.Dialer to the multidns.DialFunc
// shape (which uses string addresses; sing-box uses M.Socksaddr).
func newDialFuncFromSingbox(d N.Dialer) multidns.DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		addr := M.ParseSocksaddrHostPortStr(host, port)
		if !addr.IsValid() {
			return nil, E.New("hmrd: invalid address: ", address)
		}
		return d.DialContext(ctx, network, addr)
	}
}

func parseProtocol(s string) (multidns.Protocol, error) {
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
		return "", E.New("unsupported upstream type: ", s)
	}
}

func parseLBStrategy(s string) multidns.LBStrategy {
	switch s {
	case "weighted":
		return multidns.LBWeighted
	case "lowest_latency":
		return multidns.LBLowestLatency
	default:
		return multidns.LBRoundRobin
	}
}

// singboxLogger adapts sing-box's ContextLogger to the multidns.Logger
// interface (printf-style). The tag prefix lets operators tell which hmrd
// transport a line came from when multiple are configured.
type singboxLogger struct {
	logger log.ContextLogger
	tag    string
}

func (l *singboxLogger) Debugf(format string, args ...any) {
	l.logger.Debug(l.tag, ": ", sprintf(format, args...))
}
func (l *singboxLogger) Infof(format string, args ...any) {
	l.logger.Info(l.tag, ": ", sprintf(format, args...))
}
func (l *singboxLogger) Warnf(format string, args ...any) {
	l.logger.Warn(l.tag, ": ", sprintf(format, args...))
}
func (l *singboxLogger) Errorf(format string, args ...any) {
	l.logger.Error(l.tag, ": ", sprintf(format, args...))
}

func sprintf(format string, args ...any) string {
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}

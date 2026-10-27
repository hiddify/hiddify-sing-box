package group

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// The fallback group dials its outbounds in order and uses the first that connects. An outbound
// that fails is skipped for blacklist_timeout (one minute by default), and tried only after the
// others fail, so a dead outbound costs one failed dial per timeout, not one per connection.
// It sees dial failures only: an outbound that connects lazily (early data) and fails later is
// not caught; a URL test group suits those better. Ported from shtorm-7/sing-box-extended.

const defaultBlacklistTimeout = time.Minute

func RegisterFallback(registry *outbound.Registry) {
	outbound.Register[option.FallbackOutboundOptions](registry, C.TypeFallback, NewFallback)
}

var (
	_ adapter.OutboundGroup              = (*Fallback)(nil)
	_ adapter.PerConnectionOutboundGroup = (*Fallback)(nil)
)

type Fallback struct {
	outbound.Adapter
	outbound         adapter.OutboundManager
	logger           logger.ContextLogger
	tags             []string
	outbounds        map[string]adapter.Outbound
	blacklistTimeout time.Duration

	access    sync.Mutex
	lastUsed  string
	blacklist map[string]time.Time
}

func NewFallback(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.FallbackOutboundOptions) (adapter.Outbound, error) {
	if len(options.Outbounds) == 0 {
		return nil, E.New("missing tags")
	}
	blacklistTimeout := time.Duration(options.BlacklistTimeout)
	if blacklistTimeout <= 0 {
		blacklistTimeout = defaultBlacklistTimeout
	}
	return &Fallback{
		Adapter:          outbound.NewAdapter(C.TypeFallback, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		outbound:         service.FromContext[adapter.OutboundManager](ctx),
		logger:           logger,
		tags:             options.Outbounds,
		outbounds:        make(map[string]adapter.Outbound, len(options.Outbounds)),
		blacklistTimeout: blacklistTimeout,
		lastUsed:         options.Outbounds[0],
		blacklist:        make(map[string]time.Time),
	}, nil
}

func (s *Fallback) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	for i, tag := range s.tags {
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		s.outbounds[tag] = detour
	}
	return nil
}

func (s *Fallback) SelectsPerConnection() {}

func (s *Fallback) Now() string {
	s.access.Lock()
	defer s.access.Unlock()
	return s.lastUsed
}

func (s *Fallback) All() []string {
	return s.tags
}

// References keeps every member in use: any of them may carry the next connection.
func (s *Fallback) References() []string {
	return s.tags
}

func (s *Fallback) Selected(network string) adapter.Outbound {
	return s.outbounds[s.Now()]
}

func (s *Fallback) AttachConnection(closer io.Closer) func() {
	return func() {}
}

// order returns the members to try: those not blacklisted in order, then the blacklisted ones.
func (s *Fallback) order() []string {
	s.access.Lock()
	defer s.access.Unlock()
	now := time.Now()
	active := make([]string, 0, len(s.tags))
	var blacklisted []string
	for _, tag := range s.tags {
		if expiry, loaded := s.blacklist[tag]; loaded {
			if now.Before(expiry) {
				blacklisted = append(blacklisted, tag)
				continue
			}
			delete(s.blacklist, tag)
		}
		active = append(active, tag)
	}
	return append(active, blacklisted...)
}

func (s *Fallback) succeeded(tag string) {
	s.access.Lock()
	delete(s.blacklist, tag)
	s.lastUsed = tag
	s.access.Unlock()
}

func (s *Fallback) failed(ctx context.Context, tag string, err error) {
	s.logger.InfoContext(ctx, "fallback: ", tag, ": ", err)
	s.access.Lock()
	if _, loaded := s.blacklist[tag]; !loaded {
		s.blacklist[tag] = time.Now().Add(s.blacklistTimeout)
	}
	s.access.Unlock()
}

func (s *Fallback) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var errs []error
	for _, tag := range s.order() {
		conn, err := s.outbounds[tag].DialContext(ctx, network, destination)
		if err == nil {
			s.succeeded(tag)
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, err
		}
		s.failed(ctx, tag, err)
		errs = append(errs, E.Cause(err, tag))
	}
	return nil, E.Errors(errs...)
}

func (s *Fallback) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	var errs []error
	for _, tag := range s.order() {
		conn, err := s.outbounds[tag].ListenPacket(ctx, destination)
		if err == nil {
			s.succeeded(tag)
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, err
		}
		s.failed(ctx, tag, err)
		errs = append(errs, E.Cause(err, tag))
	}
	return nil, E.Errors(errs...)
}

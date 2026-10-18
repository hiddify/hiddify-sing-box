package group

import (
	"context"
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

func RegisterFallback(registry *outbound.Registry) {
	outbound.Register[option.FallbackOutboundOptions](registry, C.TypeFallback, NewFallback)
}

var _ adapter.OutboundGroup = (*Fallback)(nil)

type Fallback struct {
	outbound.Adapter
	ctx              context.Context
	outbound         adapter.OutboundManager
	logger           logger.ContextLogger
	tags             []string
	outbounds        map[string]adapter.Outbound
	lastUsedOutbound string
	blacklistTimeout time.Duration
	blacklist        map[string]time.Time
	mtx              sync.Mutex
}

func NewFallback(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.FallbackOutboundOptions) (adapter.Outbound, error) {
	if len(options.Outbounds) == 0 {
		return nil, E.New("missing tags")
	}
	blacklistTimeout := time.Duration(options.BlacklistTimeout)
	if blacklistTimeout == 0 {
		blacklistTimeout = time.Minute
	}
	outbound := &Fallback{
		Adapter:          outbound.NewAdapter(C.TypeFallback, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:              ctx,
		outbound:         service.FromContext[adapter.OutboundManager](ctx),
		logger:           logger,
		tags:             options.Outbounds,
		outbounds:        make(map[string]adapter.Outbound, len(options.Outbounds)),
		lastUsedOutbound: options.Outbounds[0],
		blacklistTimeout: blacklistTimeout,
		blacklist:        make(map[string]time.Time),
	}
	return outbound, nil
}

func (s *Fallback) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	for i, tag := range s.tags {
		outbound, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		s.outbounds[tag] = outbound
	}
	return nil
}

func (s *Fallback) Now() string {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return s.lastUsedOutbound
}

func (s *Fallback) All() []string {
	return s.tags
}

func (s *Fallback) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	s.mtx.Lock()
	var active, blacklisted []string
	for _, tag := range s.tags {
		if s.isBlacklisted(tag) {
			blacklisted = append(blacklisted, tag)
		} else {
			active = append(active, tag)
		}
	}
	s.mtx.Unlock()

	var err error
	for _, tag := range active {
		var conn net.Conn
		conn, err = s.outbounds[tag].DialContext(ctx, network, destination)
		if err != nil {
			s.logger.InfoContext(ctx, err)
			s.mtx.Lock()
			s.addToBlacklist(tag)
			s.mtx.Unlock()
			continue
		}
		s.mtx.Lock()
		s.lastUsedOutbound = tag
		s.mtx.Unlock()
		return conn, nil
	}
	for _, tag := range blacklisted {
		var conn net.Conn
		conn, err = s.outbounds[tag].DialContext(ctx, network, destination)
		if err != nil {
			s.logger.InfoContext(ctx, err)
			continue
		}
		s.mtx.Lock()
		delete(s.blacklist, tag)
		s.lastUsedOutbound = tag
		s.mtx.Unlock()
		return conn, nil
	}
	return nil, err
}

func (s *Fallback) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.mtx.Lock()
	var active, blacklisted []string
	for _, tag := range s.tags {
		if s.isBlacklisted(tag) {
			blacklisted = append(blacklisted, tag)
		} else {
			active = append(active, tag)
		}
	}
	s.mtx.Unlock()

	var err error
	for _, tag := range active {
		var conn net.PacketConn
		conn, err = s.outbounds[tag].ListenPacket(ctx, destination)
		if err != nil {
			s.logger.InfoContext(ctx, err)
			s.mtx.Lock()
			s.addToBlacklist(tag)
			s.mtx.Unlock()
			continue
		}
		s.mtx.Lock()
		s.lastUsedOutbound = tag
		s.mtx.Unlock()
		return conn, nil
	}
	for _, tag := range blacklisted {
		var conn net.PacketConn
		conn, err = s.outbounds[tag].ListenPacket(ctx, destination)
		if err != nil {
			s.logger.InfoContext(ctx, err)
			continue
		}
		s.mtx.Lock()
		delete(s.blacklist, tag)
		s.lastUsedOutbound = tag
		s.mtx.Unlock()
		return conn, nil
	}
	return nil, err
}

func (s *Fallback) isBlacklisted(tag string) bool {
	if s.blacklistTimeout == 0 {
		return false
	}
	expiry, ok := s.blacklist[tag]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(s.blacklist, tag)
		return false
	}
	return true
}

func (s *Fallback) addToBlacklist(tag string) {
	if s.blacklistTimeout > 0 {
		s.blacklist[tag] = time.Now().Add(s.blacklistTimeout)
	}
}

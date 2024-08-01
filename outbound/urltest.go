package outbound

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

const TimeoutDelay = 65535
const MinFailureToReset = 15

var (
	_ adapter.Outbound                = (*URLTest)(nil)
	_ adapter.OutboundGroup           = (*URLTest)(nil)
	_ adapter.InterfaceUpdateListener = (*URLTest)(nil)
)

type URLTest struct {
	myOutboundAdapter
	ctx                          context.Context
	tags                         []string
	link                         string
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	group                        *URLTestGroup
	interruptExternalConnections bool
}

func NewURLTest(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.URLTestOutboundOptions) (*URLTest, error) {
	outbound := &URLTest{
		myOutboundAdapter: myOutboundAdapter{
			protocol:     C.TypeURLTest,
			network:      []string{N.NetworkTCP, N.NetworkUDP},
			router:       router,
			logger:       logger,
			tag:          tag,
			dependencies: options.Outbounds,
		},
		ctx:                          ctx,
		tags:                         options.Outbounds,
		link:                         options.URL,
		interval:                     time.Duration(options.Interval),
		tolerance:                    options.Tolerance,
		idleTimeout:                  time.Duration(options.IdleTimeout),
		interruptExternalConnections: options.InterruptExistConnections,
	}
	if len(outbound.tags) == 0 {
		return nil, E.New("missing tags")
	}
	return outbound, nil
}

func (s *URLTest) Start() error {
	outbounds := make([]adapter.Outbound, 0, len(s.tags))
	for i, tag := range s.tags {
		detour, loaded := s.router.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		outbounds = append(outbounds, detour)
	}
	group, err := NewURLTestGroup(
		s.ctx,
		s.router,
		s.logger,
		outbounds,
		s.link,
		s.interval,
		s.tolerance,
		s.idleTimeout,
		s.interruptExternalConnections,
	)
	if err != nil {
		return err
	}
	s.group = group
	return nil
}

func (s *URLTest) PostStart() error {
	s.group.PostStart()
	return nil
}

func (s *URLTest) Close() error {
	return common.Close(
		common.PtrOrNil(s.group),
	)
}

func (s *URLTest) Now() string {
	if s.group.selectedOutboundTCP != nil {
		return s.group.selectedOutboundTCP.Tag()
	} else if s.group.selectedOutboundUDP != nil {
		return s.group.selectedOutboundUDP.Tag()
	}
	return ""
}

func (s *URLTest) All() []string {
	return s.tags
}

func (s *URLTest) URLTest(ctx context.Context) (map[string]uint16, error) {
	return s.group.URLTest(ctx)
}

func (s *URLTest) CheckOutbounds() {
	s.group.CheckOutbounds(true)
}

func (s *URLTest) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	s.group.Touch()
	var outbound adapter.Outbound
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		outbound = s.group.selectedOutboundTCP
	case N.NetworkUDP:
		outbound = s.group.selectedOutboundUDP
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	if outbound == nil {
		outbound, _ = s.group.Select(network)
	}
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	conn, err := outbound.DialContext(ctx, network, destination)
	if err == nil {
		// s.group.tcpConnectionFailureCount.Decrement(false)
		s.group.tcpConnectionFailureCount.Reset()
		return s.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}

	if !s.group.pauseManager.IsNetworkPaused() && s.group.tcpConnectionFailureCount.IncrementConditionReset(MinFailureToReset) {
		s.logger.Warn("TCP URLTest Outbound ", s.tag, " (", outboundToString(s.group.selectedOutboundTCP), ") failed to connect for ", MinFailureToReset, " times==> test proxies again!")
		s.group.selectedOutboundTCP = nil
		s.CheckOutbounds()
	}

	s.logger.ErrorContext(ctx, err)
	s.group.history.DeleteURLTestHistory(outbound.Tag())
	return nil, err
}

func (s *URLTest) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.group.Touch()
	outbound := s.group.selectedOutboundUDP
	if outbound == nil {
		outbound, _ = s.group.Select(N.NetworkUDP)
	}
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	conn, err := outbound.ListenPacket(ctx, destination)
	if err == nil {
		// s.group.udpConnectionFailureCount.Decrement(false)
		s.group.udpConnectionFailureCount.Reset()
		return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	if !s.group.pauseManager.IsNetworkPaused() && s.group.udpConnectionFailureCount.IncrementConditionReset(MinFailureToReset) {
		s.logger.Info("Hiddify! UDP URLTest Outbound ", s.tag, " (", outboundToString(s.group.selectedOutboundUDP), ") failed to connect for ", MinFailureToReset, " times==> test proxies again!")
		s.group.selectedOutboundUDP = nil
		s.group.urlTest(ctx, true)
	}
	s.logger.ErrorContext(ctx, err)
	s.group.history.DeleteURLTestHistory(outbound.Tag())
	return nil, err
}

func (s *URLTest) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	return NewConnection(ctx, s, conn, metadata)
}

func (s *URLTest) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	return NewPacketConnection(ctx, s, conn, metadata)
}

func (s *URLTest) InterfaceUpdated() {
	go s.group.CheckOutbounds(true)
	return
}

type URLTestGroup struct {
	ctx                          context.Context
	router                       adapter.Router
	logger                       log.Logger
	outbounds                    []adapter.Outbound
	link                         string
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	history                      *urltest.HistoryStorage
	checking                     atomic.Bool
	pauseManager                 pause.Manager
	selectedOutboundTCP          adapter.Outbound
	selectedOutboundUDP          adapter.Outbound
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool

	access     sync.Mutex
	ticker     *time.Ticker
	close      chan struct{}
	started    bool
	lastActive atomic.TypedValue[time.Time]

	tcpConnectionFailureCount MinZeroAtomicInt64
	udpConnectionFailureCount MinZeroAtomicInt64
}

func NewURLTestGroup(
	ctx context.Context,
	router adapter.Router,
	logger log.Logger,
	outbounds []adapter.Outbound,
	link string,
	interval time.Duration,
	tolerance uint16,
	idleTimeout time.Duration,
	interruptExternalConnections bool,
) (*URLTestGroup, error) {
	if interval == 0 {
		interval = C.DefaultURLTestInterval
	}
	if tolerance == 0 {
		tolerance = 50
	}
	if idleTimeout == 0 {
		idleTimeout = C.DefaultURLTestIdleTimeout
	}
	if interval > idleTimeout {
		return nil, E.New("interval must be less or equal than idle_timeout")
	}
	var history *urltest.HistoryStorage
	if history = service.PtrFromContext[urltest.HistoryStorage](ctx); history != nil {
	} else if clashServer := router.ClashServer(); clashServer != nil {
		history = clashServer.HistoryStorage()
	} else {
		history = urltest.NewHistoryStorage()
	}
	return &URLTestGroup{
		ctx:                          ctx,
		router:                       router,
		logger:                       logger,
		outbounds:                    outbounds,
		link:                         link,
		interval:                     interval,
		tolerance:                    tolerance,
		idleTimeout:                  idleTimeout,
		history:                      history,
		close:                        make(chan struct{}),
		pauseManager:                 service.FromContext[pause.Manager](ctx),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: interruptExternalConnections,
	}, nil
}

func (g *URLTestGroup) PostStart() {
	g.started = true
	g.lastActive.Store(time.Now())
	go g.CheckOutbounds(false)
}

func (g *URLTestGroup) Touch() {
	if !g.started {
		return
	}
	if g.ticker != nil {
		g.lastActive.Store(time.Now())
		return
	}
	g.access.Lock()
	defer g.access.Unlock()
	if g.ticker != nil {
		return
	}
	g.ticker = time.NewTicker(g.interval)
	go g.loopCheck()
}

func (g *URLTestGroup) Close() error {
	if g.ticker == nil {
		return nil
	}
	g.ticker.Stop()
	close(g.close)
	return nil
}

func (g *URLTestGroup) Select(network string) (adapter.Outbound, bool) {
	if g.selectedOutboundTCP == nil {
		g.logger.Debug(fmt.Sprintf("=================Selecting for %s current=null", network))
	} else {
		g.logger.Debug(fmt.Sprintf("=================Selecting for %s current=%s", network, RealTag(g.selectedOutboundTCP)))
	}
	for _, detour := range g.outbounds {
		if history := g.history.LoadURLTestHistory(RealTag(detour)); history != nil {
			g.logger.Trace(fmt.Sprintf("%s\t%s:%s\t%d\t%v", detour.Network(), RealTag(detour), detour.Tag(), history.Delay, history.Time))
		} else {
			g.logger.Trace(fmt.Sprintf("%s\t%s:%s\t-\t-", detour.Network(), RealTag(detour), detour.Tag()))
		}
	}
	var minDelay uint16 = TimeoutDelay
	var minOutbound adapter.Outbound
	switch network {
	case N.NetworkTCP:
		if g.selectedOutboundTCP != nil {
			if history := g.history.LoadURLTestHistory(RealTag(g.selectedOutboundTCP)); history != nil && history.Delay != TimeoutDelay && history.Delay != 0 {
				minOutbound = g.selectedOutboundTCP
				minDelay = history.Delay
			}
		}
	case N.NetworkUDP:
		if g.selectedOutboundUDP != nil {
			if history := g.history.LoadURLTestHistory(RealTag(g.selectedOutboundUDP)); history != nil && history.Delay != TimeoutDelay && history.Delay != 0 {
				minOutbound = g.selectedOutboundUDP
				minDelay = history.Delay
			}
		}
	}
	for _, detour := range g.outbounds {
		if !common.Contains(detour.Network(), network) {
			continue
		}
		history := g.history.LoadURLTestHistory(RealTag(detour))
		if history == nil || history.Delay == TimeoutDelay || history.Delay == 0 {
			continue
		}
		if minDelay == 0 || minDelay == TimeoutDelay || minDelay > history.Delay+g.tolerance {
			minDelay = history.Delay
			minOutbound = detour
		}
	}

	if minOutbound == nil {
		for _, detour := range g.outbounds {
			if !common.Contains(detour.Network(), network) {
				continue
			}
			g.logger.Debug("   Selected ", detour.Tag())
			return detour, false
		}
		return nil, false
	}
	g.logger.Debug("   Selected ", minOutbound.Tag(), " delay", minDelay)
	return minOutbound, true
}

func (g *URLTestGroup) loopCheck() {
	if time.Now().Sub(g.lastActive.Load()) > g.interval {
		g.lastActive.Store(time.Now())
		g.CheckOutbounds(false)
	}
	for {
		select {
		case <-g.close:
			return
		case <-g.ticker.C:
		}
		if time.Now().Sub(g.lastActive.Load()) > g.idleTimeout {
			g.access.Lock()
			g.ticker.Stop()
			g.ticker = nil
			g.access.Unlock()
			return
		}
		g.pauseManager.WaitActive()
		g.CheckOutbounds(false)
	}
}

func (g *URLTestGroup) CheckOutbounds(force bool) {
	_, _ = g.urlTest(g.ctx, force)
}

func (g *URLTestGroup) URLTest(ctx context.Context) (map[string]uint16, error) {
	return g.urlTest(ctx, false)
}

func (g *URLTestGroup) urlTest(ctx context.Context, force bool) (map[string]uint16, error) {
	result := make(map[string]uint16)
	if g.checking.Swap(true) {
		return result, nil
	}
	defer g.checking.Store(false)
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	checked := make(map[string]bool)
	var resultAccess sync.Mutex
	for _, detour := range g.outbounds {
		tag := detour.Tag()
		detour_ := detour
		realTag := RealTag(detour)
		if checked[realTag] {
			continue
		}
		history := g.history.LoadURLTestHistory(realTag)
		if !force && history != nil && history.Delay != TimeoutDelay && history.Delay != 0 && time.Now().Sub(history.Time) < g.interval {
			continue
		}
		checked[realTag] = true
		p, loaded := g.router.Outbound(realTag)
		if !loaded {
			continue
		}
		b.Go(realTag, func() (any, error) {
			testCtx, cancel := context.WithTimeout(g.ctx, C.TCPTimeout)
			defer cancel()
			t, err := urltest.URLTest(testCtx, g.link, p)
			if err != nil {
				g.logger.Debug("outbound ", tag, " unavailable (", TimeoutDelay, "ms): ", err)
				// g.history.DeleteURLTestHistory(realTag)
				t = TimeoutDelay
			} else {
				g.logger.Debug("outbound ", tag, " available: ", t, "ms")
			}
			g.history.StoreURLTestHistory(realTag, &urltest.History{
				Time:  time.Now(),
				Delay: t,
			})
			resultAccess.Lock()
			result[tag] = t
			g.checkForOutboundChange(detour_, t)
			resultAccess.Unlock()
			return nil, nil
		})
	}
	b.Wait()
	g.performUpdateCheck()
	return result, nil
}

func (g *URLTestGroup) checkForOutboundChange(detour adapter.Outbound, newDelay uint16) {
	if newDelay == 0 || newDelay == TimeoutDelay {
		return
	}
	var updateTCP bool
	var updateUDP bool
	if g.selectedOutboundTCP == nil {
		g.logger.Trace("no selectedOutboundTCP updating to ", detour.Tag(), " delay:", newDelay)
		updateTCP = true
	} else {
		realTag := RealTag(g.selectedOutboundTCP)
		history := g.history.LoadURLTestHistory(realTag)
		if history == nil {
			g.logger.Trace("Updating tcp outbound: no history for ", g.selectedOutboundTCP, "  updating to ", detour.Tag(), " delay:", newDelay)
			updateTCP = true
		} else if history.Delay > newDelay+g.tolerance {
			g.logger.Trace("Updating tcp outbound: old ", g.selectedOutboundTCP, " has delay of ", history.Delay, " found better! updating to ", detour.Tag(), " delay:", newDelay)
			updateTCP = true
		} else {
			g.logger.Trace("No better tcp outbound: old ", g.selectedOutboundTCP, " has delay of ", history.Delay, " old is better than the proposed ", detour.Tag(), " delay:", newDelay)
		}
	}
	if g.selectedOutboundUDP == nil {
		g.logger.Trace("no selectedOutboundTCP updating to ", detour.Tag(), " delay:", newDelay)
		updateTCP = true
	} else {
		history := g.history.LoadURLTestHistory(RealTag(g.selectedOutboundUDP))
		if history == nil {
			g.logger.Trace("Updating udp outbound: no history for ", g.selectedOutboundUDP.Tag(), "  updating to ", detour.Tag(), " delay:", newDelay)
			updateTCP = true
		} else if history.Delay > newDelay+g.tolerance {
			g.logger.Trace("Updating udp outbound: old ", g.selectedOutboundUDP.Tag(), " has delay of ", history.Delay, " found better! updating to ", detour.Tag(), " delay:", newDelay)
			updateTCP = true
		} else {
			g.logger.Trace("No better udp outbound: old ", g.selectedOutboundUDP.Tag(), " has delay of ", history.Delay, " old is better than the proposed ", detour.Tag(), " delay:", newDelay)
		}
	}
	if updateTCP || updateUDP {
		g.logger.Debug("outbound ", detour.Tag(), " delay", newDelay, "is better for udp:", updateUDP, " tcp:", updateTCP)
		g.performUpdate(detour, updateTCP, updateUDP)
	}
}
func (g *URLTestGroup) performUpdate(detour adapter.Outbound, updateTCP bool, updateUDP bool) {
	g.logger.Info("Changing outbound to ", detour.Tag(), " udp:", updateUDP, " tcp:", updateTCP)
	var updated bool
	if updateTCP {
		g.selectedOutboundTCP = detour
		g.tcpConnectionFailureCount.Reset()
		updated = true
	}
	if updateUDP {
		g.selectedOutboundUDP = detour
		g.udpConnectionFailureCount.Reset()
		updated = true
	}

	if updated {
		g.interruptGroup.Interrupt(g.interruptExternalConnections)
	}
}

func (g *URLTestGroup) performUpdateCheck() {
	var updated bool
	if outbound, exists := g.Select(N.NetworkTCP); outbound != nil && (g.selectedOutboundTCP == nil || (exists && outbound != g.selectedOutboundTCP)) {
		g.selectedOutboundTCP = outbound
		g.tcpConnectionFailureCount.Reset()
		updated = true
	}
	if outbound, exists := g.Select(N.NetworkUDP); outbound != nil && (g.selectedOutboundUDP == nil || (exists && outbound != g.selectedOutboundUDP)) {
		g.selectedOutboundUDP = outbound
		g.udpConnectionFailureCount.Reset()
		updated = true
	}
	if updated {
		g.interruptGroup.Interrupt(g.interruptExternalConnections)
	}
}

type MinZeroAtomicInt64 struct {
	access sync.Mutex
	count  int64
}

func (m *MinZeroAtomicInt64) Increment() int64 {
	m.access.Lock()
	defer m.access.Unlock()
	if m.count < 0 {
		m.count = 0
	}
	m.count++
	return m.count
}

func (m *MinZeroAtomicInt64) Decrement(useMutex bool) int64 {
	if useMutex {
		m.access.Lock()
		defer m.access.Unlock()
	}
	if m.count > 0 {
		m.count--
	}
	return m.count
}

func (m *MinZeroAtomicInt64) Get(useMutex bool) int64 {
	if useMutex {
		m.access.Lock()
		defer m.access.Unlock()
	}
	return m.count
}

func (m *MinZeroAtomicInt64) Reset() int64 {
	m.access.Lock()
	defer m.access.Unlock()
	m.count = 0
	return m.count
}
func (m *MinZeroAtomicInt64) IncrementConditionReset(condition int64) bool {
	m.access.Lock()
	defer m.access.Unlock()
	m.count++
	if m.count >= condition {
		m.count = 0
		return true
	}
	return false
}

func outboundToString(outbound adapter.Outbound) string {
	if outbound == nil {
		return "<nil>"
	}
	return outbound.Tag()
}

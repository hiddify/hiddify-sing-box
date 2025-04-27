package outbound

import (
	"context"
	"fmt"
	"net"
	"slices"
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
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

const (
	TimeoutDelay      = 65535
	MinFailureToReset = 3
)

var (
	_ adapter.Outbound                = (*URLTest)(nil)
	_ adapter.OutboundGroup           = (*URLTest)(nil)
	_ adapter.InterfaceUpdateListener = (*URLTest)(nil)
)

type URLTest struct {
	myOutboundAdapter
	ctx                          context.Context
	tags                         []string
	links                        []string
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	group                        *URLTestGroup
	interruptExternalConnections bool
}

func NewURLTest(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.URLTestOutboundOptions) (*URLTest, error) {
	links := options.URLs
	if len(links) == 0 || (options.URL != "" && !slices.Contains(links, options.URL)) {
		links = append([]string{options.URL}, links...)
	}
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
		links:                        links,
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

func (s *URLTest) Links() []string {
	return s.links
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
		s.links,
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
	if tcp := s.group.selectedOutboundTCP; tcp != nil {
		return tcp.Tag()
	} else if udp := s.group.selectedOutboundUDP; udp != nil {
		return udp.Tag()
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

func (s *URLTest) ForceRecheckOutbound(outboundTag string) error {
	if s.Tag() == outboundTag {
		_, err := s.group.urlTest(s.ctx, true)
		return err
	}
	return s.group.ForceRecheckOutbound(outboundTag)
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
		s.group.tcpConnectionFailureCount.Reset()
		return s.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}

	if !s.group.pauseManager.IsNetworkPaused() && s.group.tcpConnectionFailureCount.IncrementConditionReset(MinFailureToReset) {
		s.logger.Warn("TCP URLTest Outbound ", s.tag, " (", outboundToString(outbound), ") failed to connect for ", MinFailureToReset, " times==> test proxies again!")
		s.group.history.StoreURLTestHistory(outbound.Tag(), &urltest.History{
			Time:  time.Now(),
			Delay: TimeoutDelay,
		})
		if !s.group.checking.Load() {
			s.group.selectedOutboundUDP = nil
			s.group.selectedOutboundTCP = nil
		}
		// s.group.performUpdateCheck()
		// s.CheckOutbounds()
		s.group.urlTestEx(ctx, true, true)

	}

	s.logger.ErrorContext(ctx, err)

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
		s.group.udpConnectionFailureCount.Reset()
		return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	if !s.group.pauseManager.IsNetworkPaused() && s.group.udpConnectionFailureCount.IncrementConditionReset(MinFailureToReset) {
		s.logger.Info("Hiddify! UDP URLTest Outbound ", s.tag, " (", outboundToString(outbound), ") failed to connect for ", MinFailureToReset, " times==> test proxies again!")

		s.group.history.StoreURLTestHistory(outbound.Tag(), &urltest.History{
			Time:  time.Now(),
			Delay: TimeoutDelay,
		})
		if !s.group.checking.Load() {
			s.group.selectedOutboundUDP = nil
			s.group.selectedOutboundTCP = nil
		}
		// s.group.performUpdateCheck()
		// s.CheckOutbounds()
		s.group.urlTestEx(ctx, true, true)

	}
	s.logger.ErrorContext(ctx, err)
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
	if s.group.pauseManager.IsNetworkPaused() {
		s.logger.Error("Hiddify! Network is paused!... returning")
		return
	}

	// go s.group.CheckOutbounds(true)
	go s.group.urlTestEx(s.ctx, true, true)

	return
}

type URLTestGroup struct {
	ctx         context.Context
	router      adapter.Router
	logger      log.Logger
	outbounds   []adapter.Outbound
	links       []string
	interval    time.Duration
	tolerance   uint16
	idleTimeout time.Duration
	history     *urltest.HistoryStorage
	checking    atomic.Bool
	checkingEx  atomic.Bool // Hiddify
	// checkingOutbound             atomic.Bool // Hiddify
	pauseManager                 pause.Manager
	pauseCallback                *list.Element[pause.Callback]
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

	currentLinkIndex int

	lastForceRecheck time.Time
}

func NewURLTestGroup(
	ctx context.Context,
	router adapter.Router,
	logger log.Logger,
	outbounds []adapter.Outbound,
	links []string,
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
		interval:                     interval,
		tolerance:                    tolerance,
		idleTimeout:                  idleTimeout,
		history:                      history,
		links:                        links,
		close:                        make(chan struct{}),
		pauseManager:                 service.FromContext[pause.Manager](ctx),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: interruptExternalConnections,
	}, nil
}

func (g *URLTestGroup) onPauseUpdated(event int) {
	switch event {
	case pause.EventDevicePaused:
	case pause.EventNetworkPause: // hiddify already handled in Interface Updated
	case pause.EventDeviceWake:
		// go g.CheckOutbounds(false)
		go g.urlTestEx(g.ctx, true, true)
	case pause.EventNetworkWake: // hiddify already handled in Interface Updated
		go g.CheckOutbounds(false)
	}
}

func (g *URLTestGroup) PostStart() {
	g.started = true
	g.lastActive.Store(time.Now())
	// go g.CheckOutbounds(false)
	go g.urlTestEx(g.ctx, true, true)

	g.pauseCallback = g.pauseManager.RegisterCallback(g.onPauseUpdated)
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
	if g.pauseCallback != nil {
		g.pauseManager.UnregisterCallback(g.pauseCallback)
	}
	if g.ticker == nil {
		return nil
	}
	g.ticker.Stop()
	close(g.close)
	return nil
}

func (g *URLTestGroup) Select(network string) (adapter.Outbound, bool) {
	var minDelay uint16 = TimeoutDelay
	var minOutbound adapter.Outbound
	current := g.selectedOutboundTCP
	if network == N.NetworkUDP {
		current = g.selectedOutboundUDP
	}
	if current != nil {
		if history := g.history.LoadURLTestHistory(RealTag(current)); !isTimeout(history) {
			minOutbound = current
			minDelay = history.Delay
		}
	}

	for _, detour := range g.outbounds {
		if !common.Contains(detour.Network(), network) {
			continue
		}
		history := g.history.LoadURLTestHistory(RealTag(detour))
		if isTimeout(history) {
			continue
		}
		if minDelay == TimeoutDelay || minDelay > history.Delay+g.tolerance {
			minDelay = history.Delay
			minOutbound = detour
		}
	}
	if minOutbound == nil {
		for _, detour := range g.outbounds {
			if !common.Contains(detour.Network(), network) {
				continue
			}
			return detour, false
		}
		return nil, false
	}
	return minOutbound, true
}

func (g *URLTestGroup) loopCheck() {
	if time.Since(g.lastActive.Load()) > g.interval {
		g.lastActive.Store(time.Now())
		g.CheckOutbounds(false)
	}
	for {
		select {
		case <-g.close:
			return
		case <-g.ticker.C:
		}
		if time.Since(g.lastActive.Load()) > g.idleTimeout {
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
	return g.urlTestEx(ctx, force, false)
}

func (g *URLTestGroup) urlTestEx(ctx context.Context, force bool, force_check_even_previous_not_completed bool) (map[string]uint16, error) {
	if t := g.selectedOutboundTCP; t != nil {
		go g.urltestImp(t, nil)
	}
	if t := g.selectedOutboundUDP; t != nil && t != g.selectedOutboundTCP {
		go g.urltestImp(t, nil)
	}

	if force_check_even_previous_not_completed && time.Since(g.lastForceRecheck) < 15*time.Second {
		return make(map[string]uint16), nil
	}

	if g.checking.Swap(true) {
		if !force_check_even_previous_not_completed {
			return make(map[string]uint16), nil
		}
		if g.checkingEx.Swap(true) {
			g.performUpdateCheck()
			return make(map[string]uint16), nil
		}
		defer g.checkingEx.Store(false)
		g.lastForceRecheck = time.Now()
	}
	defer g.checking.Store(false)

	result, err := g.urlTestExImp(ctx, force, force_check_even_previous_not_completed)
	if err != nil {
		return nil, err
	}
	if !force_check_even_previous_not_completed && g.currentLinkIndex == 0 {
		for i := 1; i < len(g.links); i++ {
			result, err := g.urlTestExImp(ctx, force, force_check_even_previous_not_completed)
			if err != nil {
				return nil, err
			}
			if g.hasOneAvailableOutbound() {
				g.currentLinkIndex = i
				return result, nil
			}

		}
	}
	return result, nil
}

func (g *URLTestGroup) urlTestExImp(ctx context.Context, force bool, force_check_even_previous_not_completed bool) (map[string]uint16, error) {
	result := make(map[string]uint16)
	ipbatch, _ := batch.New(ctx, batch.WithConcurrencyNum[string](10))
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	checked := make(map[string]bool)
	var resultAccess sync.Mutex
	for _, detour := range g.outbounds {
		tag := detour.Tag()
		realTag := RealTag(detour)
		if checked[realTag] {
			continue
		}
		history := g.history.LoadURLTestHistory(realTag)
		if !force && !isTimeout(history) && time.Since(history.Time) < g.interval {
			continue
		}
		checked[realTag] = true
		p, loaded := g.router.Outbound(realTag)
		if !loaded {
			continue
		}
		b.Go(realTag, func() (any, error) {
			if !force_check_even_previous_not_completed && g.checkingEx.Load() {
				return nil, nil
			}
			t := g.urltestImp(p, ipbatch)
			resultAccess.Lock()
			result[tag] = t
			g.performOutboundUpdateCheck(detour)
			resultAccess.Unlock()
			return nil, nil
		})
	}
	b.Wait()
	ipbatch.Wait()

	g.performUpdateCheck()
}

func (g *URLTestGroup) ForceRecheckOutbound(outboundTag string) error {
	for _, detour := range g.outbounds {
		if detour.Tag() == outboundTag {
			g.urltestImp(detour, nil)
			// g.checkHistoryIp(detour)
			return nil
		}
	}
	return fmt.Errorf("Outbound not found")
}

func (g *URLTestGroup) hasOneAvailableOutbound() bool {
	for _, detour := range g.outbounds {
		if !common.Contains(detour.Network(), "tcp") {
			continue
		}
		realTag := RealTag(detour)
		history := g.history.LoadURLTestHistory(realTag)
		if isTimeout(history) {
			continue
		}
		g.logger.Debug("has one outbound ", realTag, " available: ", history.Delay, "ms")
		return true
	}
	g.logger.Debug("no available outbound ")
	return false
}

func (g *URLTestGroup) urltestImp(outbound adapter.Outbound, ipbatch *batch.Batch[string]) uint16 {
	return CheckOutbound(g.logger, g.ctx, g.history, g.router, g.links[g.currentLinkIndex], outbound, ipbatch)
}

func (g *URLTestGroup) isOutboundTimeout(outbound adapter.Outbound) bool {
	realTag := RealTag(outbound)

	if g.history == nil {
		g.logger.Debug("g.history  is null")
		return true
	}
	his := g.history.LoadURLTestHistory(realTag)
	return isTimeout(his)
}

// func (g *URLTestGroup) fetchUnknownOutboundsIpInfo() {
// 	defer func() {
// 		if r := recover(); r != nil {
// 			s := fmt.Errorf("%s panicf:\n%s", r, string(debug.Stack()))
// 			log.Error(s)
// 			<-time.After(5 * time.Second)
// 		}
// 	}()
// 	g.logger.Trace("fetchUnknownOutboundsIpInfo")
// 	g.logger.Trace("outbounds ", len(g.outbounds))

// 	b, _ := batch.New(g.ctx, batch.WithConcurrencyNum[any](10))
// 	for _, detour0 := range g.outbounds {
// 		detour := detour0

// 		realTag := RealTag(detour)
// 		g.logger.Trace("check IP ", realTag)
// 		if g.history == nil {
// 			g.logger.Trace("g.history is nil How it happened!!! ")
// 			continue
// 		}
// 		history := g.history.LoadURLTestHistory(realTag)
// 		if isTimeout(history) {
// 			g.logger.Trace(realTag, " history is timeout")
// 			continue
// 		}

// 		if history.IpInfo != nil {
// 			g.logger.Trace(realTag, "outbound has already ip ", fmt.Sprint(history.IpInfo))
// 			continue
// 		}
// 		g.logger.Trace("getting IP... ", realTag)
// 		b.Go(realTag+"ip", func() (any, error) {
// 			defer func() {
// 				if r := recover(); r != nil {
// 					s := fmt.Errorf("%s panic: %s\n%s", realTag, r, string(debug.Stack()))
// 					log.Error(s)
// 					<-time.After(5 * time.Second)
// 				}
// 			}()
// 			g.logger.Trace("get IP start ", realTag)
// 			g.checkHistoryIp(detour)
// 			g.logger.Trace("get IP end ", realTag)
// 			return "", nil
// 		})
// 	}
// 	go b.Wait()
// }

func (g *URLTestGroup) performUpdateCheck() {
	// if g.checkingOutbound.Swap(true) {
	// 	return
	// }
	// defer g.checkingOutbound.Store(false)

	var tcpOutbound, udpOutbound adapter.Outbound
	if outbound, exists := g.Select(N.NetworkTCP); outbound != nil && (g.selectedOutboundTCP == nil || (exists && outbound != g.selectedOutboundTCP)) {
		tcpOutbound = outbound
	}
	if outbound, exists := g.Select(N.NetworkUDP); outbound != nil && (g.selectedOutboundUDP == nil || (exists && outbound != g.selectedOutboundUDP)) {
		udpOutbound = outbound
	}
	g.forceUpdateOutbound(tcpOutbound, udpOutbound)
}

func (g *URLTestGroup) forceUpdateOutbound(tcp adapter.Outbound, udp adapter.Outbound) bool {
	update := false
	if tcp != nil && g.selectedOutboundTCP != tcp {
		g.selectedOutboundTCP = tcp
		g.tcpConnectionFailureCount.Reset()
		// go g.checkHistoryIp(g.selectedOutboundTCP)
		update = true

	}
	if udp != nil && g.selectedOutboundUDP != udp {
		g.selectedOutboundUDP = udp
		g.udpConnectionFailureCount.Reset()
		update = true
	}
	if update {
		g.interruptGroup.Interrupt(g.interruptExternalConnections)
	}
	return update
}

// isTimeout ensures the history is valid for an update check
func isTimeout(history *urltest.History) bool {
	return history == nil || history.Delay == TimeoutDelay || history.Delay == 0
}

func (g *URLTestGroup) performOutboundUpdateCheck(outbound adapter.Outbound) {
	tcpOutbound, shouldReselectTCP := g.getPreferredOutbound(outbound, g.selectedOutboundTCP, N.NetworkTCP)
	udpOutbound, shouldReselectUDP := g.getPreferredOutbound(outbound, g.selectedOutboundUDP, N.NetworkUDP)
	if shouldReselectTCP {
		tcpOutbound, _ = g.Select(N.NetworkTCP)
	}
	if shouldReselectUDP {
		udpOutbound, _ = g.Select(N.NetworkUDP)
	}

	g.forceUpdateOutbound(tcpOutbound, udpOutbound)
}

// getPreferredOutbound selects the best outbound based on history and network type
func (g *URLTestGroup) getPreferredOutbound(newOutbound, selectedOutbound adapter.Outbound, networkType string) (outbound adapter.Outbound, shouldReselect bool) {
	if newOutbound == nil {
		return nil, false
	}

	if !contains(newOutbound.Network(), networkType) {
		return nil, false
	}

	newHistory := g.history.LoadURLTestHistory(RealTag(newOutbound))
	if isTimeout(newHistory) {
		if newOutbound == selectedOutbound {
			return nil, true
		}
		return nil, false
	}

	if selectedOutbound == nil {
		return newOutbound, false
	}

	selectedHistory := g.history.LoadURLTestHistory(RealTag(selectedOutbound))
	if isTimeout(selectedHistory) {
		return newOutbound, false
	}

	if newHistory == nil || selectedHistory == nil {
		return nil, false
	}

	if newHistory.Delay+g.tolerance < selectedHistory.Delay {
		return newOutbound, false
	}

	return selectedOutbound, false
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
	if m.count == 0 {
		return 0
	}
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

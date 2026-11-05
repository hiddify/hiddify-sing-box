package monitoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"

	"github.com/sagernet/sing-box/hiddify/ipinfo"
	"github.com/sagernet/sing/common/x/list"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service/pause"
)

const TimeoutDelay uint16 = 65535

var _ adapter.ConnectionTracker = (*OutboundMonitoring)(nil)
var _ adapter.LifecycleService = (*OutboundMonitoring)(nil)
var _ adapter.InterfaceUpdateListener = (*OutboundMonitoring)(nil)

const (
	defaultWorkerCount    = 10
	defaultDebounceWindow = 500 * time.Millisecond
	defaultURLTestTimeout = 5 * time.Second
	defaultIdleTimeout    = 10 * time.Minute
	defaultInterval       = 5 * time.Minute
	defaultURLTest        = "https://www.gstatic.com/generate_204"
)

// H: a test broken by a network reset waits this long, for the reset to end, then runs again
const networkResetWait = time.Second

// H: how long after the last network change every outbound is tested again
const networkRetestDelay = 2 * time.Second

// H: a test whose outbound or detour is not ready is tried again after dependencyWait, at most
// dependencyWaits times; then it runs anyway, so a detour that never gets a result cannot hold it
const (
	dependencyWait  = 3 * time.Second
	dependencyWaits = 10
)

// func RegisterService(registry *boxService.Registry) {
// 	boxService.Register[option.MonitoringOptions](registry, C.TypeOutboundMonitor, func(ctx context.Context, logger log.ContextLogger, tag string, options option.MonitoringOptions) (adapter.Service, error) {
// 		return NewOutboundMonitoring(ctx, logger, tag, options)
// 	})
// }

func Get(ctx context.Context) *OutboundMonitoring {
	return service.PtrFromContext[OutboundMonitoring](ctx)
}

// OutboundMonitoring orchestrates URL testing and traffic sampling for outbounds.
type OutboundMonitoring struct {
	endpointManager  adapter.EndpointManager
	outboundManager  adapter.OutboundManager
	logger           log.ContextLogger
	cache            adapter.CacheFile
	ctx              context.Context
	cancel           context.CancelFunc
	tag              string
	pause            pause.Manager
	pauseCallback    *list.Element[pause.Callback]
	started          bool
	urls             []string
	ipInfoURL        string
	ipv6Access       sync.Mutex                // H: guards ipv6
	ipv6             map[string]*ipv6Knowledge // H: what is known of each outbound's IPv6, see h_ipv6.go
	verifyIPv6       bool                      // H: option.MonitoringOptions.VerifyIPv6
	ipv6Declared     map[string]bool           // H: option.MonitoringOptions.IPv6Declared
	currentLinkIndex atomic.Uint32
	access           sync.Mutex
	idleTimeout      time.Duration
	lastActive       common.TypedValue[time.Time]
	workersRunning   atomic.Bool
	mainInterval     time.Duration
	debounceWindow   time.Duration
	urlTestTimeout   time.Duration
	onDemand         []time.Duration // H: see option.MonitoringOptions.OnDemandTimeouts
	workersCount     int
	history          adapter.URLTestHistoryStorage

	mainTicker *time.Ticker

	normalQueue chan *testTask

	// H: outbounds and groups, replaced as a whole when outbounds are hot reloaded
	registry     atomic.Pointer[monitoringRegistry]
	reloadAccess sync.Mutex

	cacheDirty atomic.Bool

	cycleSeq     atomic.Uint64 // H: a typed atomic, 8-byte aligned also on 32-bit ARM, where a bare uint64 used with atomic.AddUint64 panics
	cycleRunning atomic.Bool
	networkSeq   atomic.Uint64 //H: counts network resets, see executeTask

	networkRetest *time.Timer  // H: the pending retest after a network change, guarded by access
	cycleAgain    atomic.Bool  // H: a cycle that ran during a network change runs once more
	periodicCycle atomic.Bool  // H: the running cycle is a regular one of the schedule, see h_cycle.go
	cycleStarted  atomic.Value // H: time.Time, see CycleStartedAt

	workerWG    sync.WaitGroup
	schedulerWG sync.WaitGroup
	closerOnce  sync.Once
}

// InterfaceUpdated implements [adapter.InterfaceUpdateListener]. H: called by the network reset,
// which closes every connection, the running URL tests included.
func (m *OutboundMonitoring) InterfaceUpdated(ctx context.Context) {
	m.networkSeq.Add(1)
}

// NetworkChanged makes every outbound be tested again once the network has settled: what was
// measured on the previous network says nothing about the new one, or about having none. A burst
// of changes is one retest.
func (m *OutboundMonitoring) NetworkChanged() {
	m.access.Lock()
	defer m.access.Unlock()
	if !m.started {
		return
	}
	if m.networkRetest != nil {
		m.networkRetest.Reset(networkRetestDelay)
		return
	}
	m.networkRetest = time.AfterFunc(networkRetestDelay, m.retestAll)
}

func (m *OutboundMonitoring) retestAll() {
	m.access.Lock()
	m.networkRetest = nil
	m.access.Unlock()
	select {
	case <-m.ctx.Done():
		return
	default:
	}
	m.logger.Info("network changed, testing every outbound again")
	for _, state := range m.reg().outbounds {
		state.mu.Lock()
		state.invalid = true
		state.mu.Unlock()
	}
	m.Touch()
	m.periodicCycle.Store(false) //H: the results are of the old network; the groups take the new ones at once
	if !m.startCycleOnce() {
		// a cycle is running: its results may predate the change, so it runs once more
		m.cycleAgain.Store(true)
	}
}

// Name implements [adapter.LifecycleService].
func (m *OutboundMonitoring) Name() string {
	return "outbound-monitoring"
}

func (m *OutboundMonitoring) OutboundsHistory(groupTag string) map[string]*adapter.URLTestHistory {

	histories := make(map[string]*adapter.URLTestHistory)

	registry := m.reg()
	if registry == nil { // before Start
		return histories
	}
	grp, ok := registry.groups[groupTag]
	if !ok {
		return histories
	}
	//m.logger.Debug("collecting history for group ", groupTag, " with ", len(grp.outbounds), " outbounds")
	for outboundTag := range grp.outbounds {
		histories[outboundTag] = m.confirmed(groupTag, outboundTag, m.getUrlTest(outboundTag)) //H
		// m.logger.Error("checking history for outbound ", outboundTag)

	}
	return histories
}

func (m *OutboundMonitoring) getUrlTest(outboundTag string) *adapter.URLTestHistory {
	state, ok := m.reg().outbounds[outboundTag]
	if !ok {
		return nil
	}

	if grp, ok := m.reg().groups[outboundTag]; ok {
		realtag := RealTag(state.outbound)
		//m.logger.Debug("outbound ", outboundTag, " is a group, checking group ", grp.tag, " with real tag ", realtag)
		if realtag != "" && realtag != outboundTag {
			return m.getUrlTest(realtag)
		}

		return m.getMinGroupOutboundHistory(grp.tag)

	}
	state.mu.Lock()
	his := state.history
	his.IsFromCache = state.from_cache
	state.mu.Unlock()
	return &his

}

func (m *OutboundMonitoring) getMinGroupOutboundHistory(groupTag string) *adapter.URLTestHistory {
	grp, ok := m.reg().groups[groupTag]
	if !ok {
		return nil
	}
	var minHis *adapter.URLTestHistory
	var minHisFromCache *adapter.URLTestHistory
	for outboundTag := range grp.outbounds {
		his := m.getUrlTest(outboundTag)
		if his == nil || his.Delay == 0 {
			continue
		}
		if !his.IsFromCache {
			if minHis == nil {
				minHis = his
			} else if his.Delay < minHis.Delay {
				minHis.Delay = his.Delay
				minHis.IpInfo, minHis.IpInfoFromCache = his.IpInfo, his.IpInfoFromCache //H
			} else if minHis.IpInfo == nil {
				minHis.IpInfo, minHis.IpInfoFromCache = his.IpInfo, his.IpInfoFromCache //H
			}
		} else {
			if minHisFromCache == nil {
				minHisFromCache = his
			} else if his.Delay < minHisFromCache.Delay {
				minHisFromCache.Delay = his.Delay
				minHisFromCache.IpInfo, minHisFromCache.IpInfoFromCache = his.IpInfo, his.IpInfoFromCache //H
			} else if minHisFromCache.IpInfo == nil {
				minHisFromCache.IpInfo, minHisFromCache.IpInfoFromCache = his.IpInfo, his.IpInfoFromCache //H
			}
		}
	}

	final := minHis
	if minHis == nil || minHis.Delay >= TimeoutDelay {
		final = minHisFromCache
	} else if minHisFromCache != nil && minHis.IpInfo == nil {
		final.IpInfo, final.IpInfoFromCache = minHisFromCache.IpInfo, minHisFromCache.IpInfoFromCache //H
	}

	return final

}

func (m *OutboundMonitoring) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	m.Touch()
	return conn
}
func (m *OutboundMonitoring) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	m.Touch()
	return conn
}

type noopFlowTracker struct{}

func (noopFlowTracker) AttachFlow(tun.FlowHandle)     {}
func (noopFlowTracker) CountForward(int)              {}
func (noopFlowTracker) CountReverse(int)              {}
func (noopFlowTracker) FlowEstablished()              {}
func (noopFlowTracker) CloseFlow(tun.FlowCloseReason) {}

func (m *OutboundMonitoring) RoutedFlow(ctx context.Context, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) tun.FlowTracker {
	m.Touch()
	return noopFlowTracker{}
}

// NewOutboundMonitoring creates and starts a monitoring instance.
func NewOutboundMonitoring(ctx context.Context, logger log.ContextLogger, options option.MonitoringOptions) (*OutboundMonitoring, error) {
	if options.Interval <= 0 {
		options.Interval = badoption.Duration(defaultInterval)
	}
	if options.Workers <= 0 {
		options.Workers = defaultWorkerCount
	}
	if options.URLTestTimeout <= 0 {
		options.URLTestTimeout = badoption.Duration(defaultURLTestTimeout)
	}
	if options.IdleTimeout <= 0 {
		options.IdleTimeout = badoption.Duration(defaultIdleTimeout)
	}
	if options.DebounceWindow <= 0 {
		options.DebounceWindow = badoption.Duration(defaultDebounceWindow)
	}
	onDemand := onDemandTimeouts(options.OnDemandTimeouts) //H

	cloned := append([]string(nil), options.URLs...)
	if len(cloned) == 0 {
		cloned = []string{defaultURLTest}
	}

	var history adapter.URLTestHistoryStorage
	if historyFromCtx := service.PtrFromContext[urltest.HistoryStorage](ctx); historyFromCtx != nil {
		history = historyFromCtx
	} else if clashServer := service.FromContext[adapter.ClashServer](ctx); clashServer != nil {
		history = clashServer.HistoryStorage()
	} else {
		history = urltest.NewHistoryStorage()
	}

	ctx, cancel := context.WithCancel(ctx)
	m := &OutboundMonitoring{
		ctx:             ctx,
		cancel:          cancel,
		urls:            cloned,
		ipInfoURL:       options.IpInfoURL,
		ipv6:            make(map[string]*ipv6Knowledge), //H
		verifyIPv6:      options.VerifyIPv6,              //H
		ipv6Declared:    options.IPv6Declared,            //H
		pause:           service.FromContext[pause.Manager](ctx),
		started:         false,
		logger:          logger,
		outboundManager: service.FromContext[adapter.OutboundManager](ctx),
		endpointManager: service.FromContext[adapter.EndpointManager](ctx),

		history: history,

		mainInterval:   options.Interval.Build(),
		idleTimeout:    options.IdleTimeout.Build(),
		workersCount:   options.Workers,
		urlTestTimeout: options.URLTestTimeout.Build(),
		debounceWindow: options.DebounceWindow.Build(),
		onDemand:       onDemand, //H

		normalQueue: make(chan *testTask, 10000),
	}
	m.registry.Store(newMonitoringRegistry())
	if service.FromContext[adapter.IPv6Capability](ctx) == nil { //H: what the DNS router and the route ask
		service.MustRegister[adapter.IPv6Capability](ctx, m) //H
	} //H

	return m, nil
}

func (m *OutboundMonitoring) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		scope.Add(m.Close) // H: closed with the box
	}
	m.logger.Info("starting outbound monitoring ", stage)
	switch stage {
	case adapter.StartStateInitialize:
		m.cache = service.FromContext[adapter.CacheFile](m.ctx)
		registry, err := m.buildRegistry(newMonitoringRegistry())
		if err != nil {
			return err
		}
		m.registry.Store(registry)
		m.logger.Info("registered ", len(registry.outbounds), " outbounds for monitoring")
		m.logger.Info("registered ", len(registry.groups), " outbound groups for monitoring")
		m.loadHistory()
		m.seedIPv6Knowledge() //H: what the cache and the links' declarations say
	case adapter.StartStatePostStart:
		for i := 0; i < m.workersCount; i++ {
			m.workerWG.Add(1)
			go m.workerLoop()
		}
		for _, grp := range m.reg().groups {
			m.schedulerWG.Add(1)
			go m.groupNotifierLoop(grp)
		}

		m.started = true
		m.testSelections() // H: the selected proxies first, before the cycle Touch starts
		m.Touch()
	}

	return nil
}

func (m *OutboundMonitoring) startTimerWorkers() {
	if !m.workersRunning.CompareAndSwap(false, true) {
		return
	}
	m.mainTicker = time.NewTicker(m.mainInterval)
	m.lastActive.Store(time.Now()) // H: the Touch that restarts the workers is activity too

	m.pauseCallback = pause.RegisterTicker(m.pause, m.mainTicker, m.mainInterval, nil)
	m.schedulerWG.Add(1)
	go m.scheduleLoop(m.mainTicker) // H: the field is cleared by stopTimerWorkers
}
func (m *OutboundMonitoring) stopTimerWorkers() {
	m.access.Lock() // H: mainTicker is also read by Touch
	defer m.access.Unlock()
	if !m.workersRunning.CompareAndSwap(true, false) {
		return
	}
	m.mainTicker.Stop()
	m.mainTicker = nil
	if m.cacheDirty.Load() {
		m.saveHistory()
	}

	m.pause.UnregisterCallback(m.pauseCallback)
}

// SignalChange reports that an outbound changed without a URL test, e.g. a selector switched
// to another outbound. Subscribers of every group containing it, or containing an outbound
// that depends on it (detour chain), get an event; those dependents are re-tested because
// their path changed. Non-blocking.
//
// Selection is published to subscribers immediately. The debounced notifyCh path is for
// URL-test bursts and must not delay SelectOutbound observers (OutboundsInfo streams).
func (m *OutboundMonitoring) SignalChange(outboundTag string) error {
	if m.getState(outboundTag) == nil {
		return errors.New("outbound not registered")
	}
	m.signalChange(outboundTag, make(map[string]bool))
	m.flushSelectionEvents(outboundTag)
	m.testParents(outboundTag, true)
	m.testSelected(outboundTag) // H: the new selection itself, now
	return nil
}

// flushSelectionEvents publishes Priority GroupEvents so AllProxiesInfoStream can skip its
// debounce and other subscribers observe the new Selected tag without waiting for
// groupNotifierLoop debounce.
func (m *OutboundMonitoring) flushSelectionEvents(outboundTag string) {
	seen := make(map[string]bool)
	flush := func(tag string) {
		if seen[tag] {
			return
		}
		seen[tag] = true
		m.emitGroupEventPriority(tag, time.Time{})
	}
	if _, isGroup := m.reg().groups[outboundTag]; isGroup {
		flush(outboundTag)
	}
	if state := m.getState(outboundTag); state != nil {
		for _, tag := range state.groupTags {
			flush(tag)
		}
	}
	// Catch-all "" group is what AllProxiesInfoStream / MainOutboundsInfo subscribe to.
	flush("")
}

func (m *OutboundMonitoring) signalChange(outboundTag string, visited map[string]bool) {
	if visited[outboundTag] {
		return
	}
	visited[outboundTag] = true
	if _, isGroup := m.reg().groups[outboundTag]; isGroup {
		m.emitGroupEvent([]string{outboundTag})
	}
	state := m.getState(outboundTag)
	if state == nil {
		return
	}
	m.emitGroupEvent(state.groupTags)
	for _, dependent := range state.dependenciesInverse {
		m.signalChange(dependent, visited)
	}
}
func (m *OutboundMonitoring) TestNow(outboundTag string) error {
	m.testParents(outboundTag, true)
	return m.testNow(outboundTag, true, "asked for by the app") //H
}
func (m *OutboundMonitoring) testNow(outboundTag string, priority bool, reason string) error { //H: reason
	if grp, ok := m.reg().groups[outboundTag]; ok {
		for tag := range grp.outbounds {
			m.testNow(tag, false, "member of "+outboundTag+", "+reason) //H
		}
	} else {
		state := m.getState(outboundTag)
		if state == nil {
			return errors.New("outbound not registered")
		}

		task := &testTask{
			outboundTag: outboundTag,
			cycleID:     m.cycleSeq.Load(),
			priority:    priority,
			staged:      priority, //H
			reason:      reason,   //H
		}

		if !m.enqueueTask(task) {
			m.logger.Info("MONITORING ", outboundTag, ": not tested again (", reason, "): a test of it is queued or running, or it is unknown") //H
		}
	}
	return nil
}

func (m *OutboundMonitoring) testParents(outboundTag string, first bool) {
	state := m.getState(outboundTag)
	if state == nil {
		return
	}
	if _, ok := m.reg().groups[outboundTag]; !ok && !first {
		m.testNow(outboundTag, true, "goes through what changed") //H
	}
	for _, dep := range state.dependenciesInverse {
		m.testParents(dep, false)
	}
}

// InvalidateTest marks the cached test result as invalid so it will be retested.
func (m *OutboundMonitoring) InvalidateTest(outboundTag string) error {
	state := m.getState(outboundTag)
	if state == nil {
		return errors.New("outbound not registered")
	}
	state.mu.Lock()
	state.invalid = true
	state.mu.Unlock()

	m.enqueueTask(&testTask{
		outboundTag: outboundTag,
		cycleID:     m.cycleSeq.Load(),
		priority:    true,
		reason:      "a connection through it failed", //H
	})

	return nil
}

func (m *OutboundMonitoring) SubscribeGroup(groupTag string) (observer <-chan GroupEvent, err error) {

	if g, ok := m.reg().groups[groupTag]; ok {
		// Buffer a few events so a selection flush is not dropped while the subscriber
		// is coalescing the previous URL-test update.
		return g.observer.Subscribe(8), nil
	}
	return nil, E.New("group not found ", groupTag)
}
func (m *OutboundMonitoring) UnsubscribeGroup(groupTag string, observer <-chan GroupEvent) (err error) {
	if g, ok := m.reg().groups[groupTag]; ok {
		g.observer.Unsubscribe(observer)
		return nil
	}
	return E.New("group not found ", groupTag)
}

func (m *OutboundMonitoring) Close() error {
	m.closerOnce.Do(func() {
		m.stopTimerWorkers()
		m.access.Lock()
		if m.networkRetest != nil {
			m.networkRetest.Stop()
			m.networkRetest = nil
		}
		m.access.Unlock()

		// close(m.priorityQueue)
		// close(m.normalQueue)
		for _, g := range m.reg().groups {
			if g.observer != nil {
				g.observer.Close()
			}
		}
		m.cancel()
		m.workerWG.Wait()
		m.schedulerWG.Wait()

	})
	return nil
}

func (m *OutboundMonitoring) scheduleLoop(ticker *time.Ticker) {
	m.logger.Info("outbound monitoring schedule loop started")
	m.startCycleOnce()
	for {
		select {
		case <-m.ctx.Done():
			m.schedulerWG.Done()
			return
		case <-ticker.C:
			if time.Since(m.lastActive.Load()) > m.idleTimeout {
				m.schedulerWG.Done()
				m.stopTimerWorkers()
				return
			}
			m.startCycle(true) //H: a regular cycle, during which the groups hold

		}
	}
}

// workerLoop runs the cycle's tests, workers at a time. A test asked for (priority) does not
// wait for a worker: enqueueTask runs it at once. //H
func (m *OutboundMonitoring) workerLoop() {
	defer m.workerWG.Done()
	for {
		select {
		case <-m.ctx.Done():
			return
		case task := <-m.normalQueue:
			m.executeTask(task)
		}
	}
}

func (m *OutboundMonitoring) executeTask(task *testTask) {
	select {
	case <-m.ctx.Done():
		return
	default:
	}

	state := m.reg().outbounds[task.outboundTag]
	if state == nil {
		return
	}

	state.mu.Lock()
	if state.testing { //H: a test of it runs: its result is this one's, see joinRunningTest
		state.mu.Unlock()
		if task.priority {
			m.joinRunningTest(task, state)
		} else {
			go m.joinRunningTest(task, state) // the worker is not held for the running test
		}
		return
	}
	state.testing = true
	state.testDone = make(chan struct{}) //H
	state.mu.Unlock()
	defer func() {
		state.mu.Lock()
		state.testing = false
		close(state.testDone) //H
		state.mu.Unlock()
	}()
	if task.waits < dependencyWaits && (!adapter.IsReady(state.outbound) || !m.dependenciesReady(state)) { //H
		reason := "not ready"
		if adapter.IsReady(state.outbound) {
			reason = "detour not ready"
		}
		m.logger.Info("outbound ", task.outboundTag, " is ", reason, ", skipping test")
		go func() {
			select {
			case <-m.ctx.Done():
				return
			case <-time.After(dependencyWait): //H
			}
			state.mu.Lock()
			task.waits++ //H
			task.cycleID++
			state.priorityQueued = false // H: the retry queues it again; left set, every URL test of it was dropped
			state.mu.Unlock()
			m.enqueueTask(task)
		}()
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		state.mu.Lock()
		worked := state.workedLocked()                                 //H
		known, knownFromCache := state.history.Delay, state.from_cache //H
		state.mu.Unlock()
		m.logger.Info("MONITORING test ", task.outboundTag, ": ", task.reason, testKind(task, known, knownFromCache))       //H
		interim := func(history adapter.URLTestHistory, tentative bool) { m.applyInterim(task, state, history, tentative) } //H
		networkSeq := m.networkSeq.Load()
		delay, err := m.tester(m.ctx, task.outboundTag, interim, task.staged, worked)
		for err != nil && m.networkSeq.Load() != networkSeq { //H: a network reset broke the test
			m.logger.Info("outbound ", task.outboundTag, " test broken by a network reset, testing again")
			networkSeq = m.networkSeq.Load()
			select {
			case <-m.ctx.Done():
				return
			case <-time.After(networkResetWait):
			}
			delay, err = m.tester(m.ctx, task.outboundTag, interim, task.staged, worked)
		}
		m.settle(task, state, delay, err, worked) //H
	}()
	select {
	case <-m.ctx.Done():
		return
	case <-done:
	case <-time.After(m.testHardLimit(task)): //H: the outbound ignored its deadline; see settleLate
		m.settleLate(task, state)
	}

}

// tester runs the URL test and, when it answers, the IP lookup. The delay goes to interim as
// soon as the URL test answers, before the lookup, which can take as long again. worked says
// whether the outbound has a working result of this run, see stagedURLTest. //H
func (m *OutboundMonitoring) tester(parent context.Context, tag string, interim func(adapter.URLTestHistory, bool), staged bool, worked bool) (adapter.URLTestHistory, error) {
	out, ok := m.reg().outbounds[tag]
	if !ok {
		return adapter.URLTestHistory{Delay: 0}, errors.New("outbound not registered")
	}

	idx := m.currentLinkIndex.Load()
	factor := m.timeoutFactor(out.outbound) //H

	var ( //H
		delay uint16
		err   error
	)
	if staged { //H
		delay, err = m.stagedURLTest(parent, m.urls[idx], out.outbound, interim, worked)
	} else {
		ctx, cancel := context.WithTimeout(parent, factor*m.urlTestTimeout) //H
		defer cancel()
		delay, err = urltest.URLTest(ctx, m.urls[idx], out.outbound)
	}

	his := adapter.URLTestHistory{
		Time:  time.Now(),
		Delay: delay,
	}
	if err != nil || delay >= TimeoutDelay {
		his.Delay = TimeoutDelay
		m.logger.Warn("MONITORING result ", tag, ": failed: ", err) //H
		return his, err
	}
	select {
	case <-parent.Done():
		return his, parent.Err()
	default:
	}
	if interim != nil { //H
		interim(his, false)
	}
	if m.verifyIPv6 && (out.history.IPv6 == nil || out.history.IPv6FromCache) { //H: once per run, like the IP lookup
		his.IPv6 = m.verifyIPv6Of(parent, out, m.urls[idx]) //H
	} //H
	if out.history.IpInfo == nil || out.history.IpInfoFromCache { //H: until looked up in this run

		ctx, cancel2 := context.WithTimeout(parent, factor*m.urlTestTimeout) //H
		defer cancel2()

		newip, t, err := ipinfo.GetIpInfo(m.logger, ctx, out.outbound, m.ipInfoURL)
		if err == nil {
			his.IpInfo = mergeIpInfo(out.history.IpInfo, newip)
			if t < his.Delay {
				his.Delay = t
			}
		}
	}
	if his.IpInfo != nil {
		m.logger.Info("MONITORING result ", tag, ": ", his.Delay, " ms, IP ", fmt.Sprint(his.IpInfo)) //H
	} else {
		m.logger.Info("MONITORING result ", tag, ": ", his.Delay, " ms, IP unknown") //H
	}
	return his, nil
}

func (m *OutboundMonitoring) startCycleOnce() bool {
	return m.startCycle(false) //H
}

func (m *OutboundMonitoring) startCycle(periodic bool) bool { //H
	if !m.cycleRunning.CompareAndSwap(false, true) {
		return false
	}
	m.periodicCycle.Store(periodic)  //H
	m.cycleStarted.Store(time.Now()) //H
	go func() {
		defer m.endCycle() //H: tells the groups, which held their selection during it
		m.logger.Info("starting regular outbound monitoring cycle")
		m.runCycle()
		for m.cycleAgain.Swap(false) { // periodicCycle is already false: retestAll cleared it
			m.logger.Info("running the monitoring cycle again after a network change")
			m.runCycle()
		}
	}()
	return true
}

func (m *OutboundMonitoring) runCycle() {
	cycleID := m.cycleSeq.Add(1)
	tags := m.collectCycleTargets()
	m.logger.Info("MONITORING cycle ", cycleID, " starts: ", len(tags), " outbounds due (periodic: ", m.periodicCycle.Load(), ")") //H
	defer m.logger.Info("MONITORING cycle ", cycleID, " ends")                                                                     //H

	if len(tags) == 0 {
		return
	}
	defer func() {
		if m.cacheDirty.Swap(false) {
			m.saveHistory()
		}
	}()

	for idx, _ := range m.urls {
		outcomes := m.runStage(cycleID, tags)
		success := 0
		for _, result := range outcomes {
			if result.err == nil {
				success++
			}
		}
		if success > 0 || idx == len(m.urls)-1 {
			return
		}
		m.currentLinkIndex.Store((m.currentLinkIndex.Load() + 1) % uint32(len(m.urls)))
	}
}

func (m *OutboundMonitoring) runStage(cycleID uint64, tags []string) []testOutcome {
	resultCh := make(chan testOutcome, len(tags))

	expected := 0
	reason := fmt.Sprint("cycle ", cycleID) //H
	for _, tag := range tags {
		state := m.getState(tag)
		if state == nil {
			continue
		}

		task := &testTask{
			outboundTag: tag,
			cycleID:     cycleID,
			priority:    false,
			resultCh:    resultCh,
			reason:      reason, //H
		}
		if m.enqueueTask(task) {
			expected++
		}

	}

	results := make([]testOutcome, 0, expected)

	for expected > 0 {
		select {
		case <-m.ctx.Done():
			return results
		case r := <-resultCh:
			results = append(results, r)
			expected--
		}
	}

	return results
}

func (m *OutboundMonitoring) enqueueTask(task *testTask) bool {

	select {
	case <-m.ctx.Done():
		return false
	default:
	}
	state, ok := m.reg().outbounds[task.outboundTag]
	if !ok {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()

	if task.priority {
		if state.priorityQueued {
			return false
		}
		state.priorityQueued = true
	} else {
		if state.enqueuedCycle == task.cycleID {
			return false
		}
		state.enqueuedCycle = task.cycleID
		state.queued = true
	}
	if task.priority {
		// H: asked for, so run now, beside the cycle's tests, not behind them: the workers may all
		// be busy with a cycle of timeouts for seconds
		go m.executeTask(task)
		return true
	}
	select {
	case m.normalQueue <- task:
		return true
	default:
		return false
	}
}

func (m *OutboundMonitoring) applyResult(outcome testOutcome) *adapter.URLTestHistory {
	select {
	case <-m.ctx.Done():
		return nil
	default:
	}
	state, ok := m.reg().outbounds[outcome.outboundTag]
	if !ok {
		return nil
	}
	state.mu.Lock()
	defer state.mu.Unlock()

	state.queued = false
	state.priorityQueued = false
	state.enqueuedCycle = 0
	state.invalid = outcome.err != nil
	state.lastURL = outcome.url
	if (outcome.history.Delay != state.history.Delay) || state.history.IpInfo == nil || (outcome.history.IpInfo != nil) {
		m.cacheDirty.Store(true)
	}
	state.history.Delay = outcome.history.Delay
	state.history.Time = outcome.history.Time
	state.history.Error = testError(outcome.err) //H
	state.from_cache = false
	state.tentative = false //H
	if outcome.history.IpInfo != nil {
		state.history.IpInfo = outcome.history.IpInfo
		state.history.IpInfoFromCache = false //H
	}
	if outcome.history.IPv6 != nil { //H: verified at this test
		state.history.IPv6 = outcome.history.IPv6                //H
		state.history.IPv6FromCache = false                      //H
		m.cacheDirty.Store(true)                                 //H
		m.recordIPv6(outcome.outboundTag, *outcome.history.IPv6) //H
	} //H
	m.history.StoreURLTestHistory(outcome.outboundTag, &state.history)

	m.emitGroupEvent(state.groupTags)
	return &state.history
}

func mergeIpInfo(old, new *ipinfo.IpInfo) *ipinfo.IpInfo {
	if old == nil {
		return new
	}
	if new == nil {
		return old
	}
	new2 := *new // copy
	if new2.CountryCode == "" {
		new2.CountryCode = old.CountryCode
	}
	if new2.Org == "" {
		new2.Org = old.Org
	}
	return &new2
}

func (m *OutboundMonitoring) collectCycleTargets() []string {

	tags := make([]string, 0, len(m.reg().outbounds))

	delays := make(map[string]uint16, len(tags))

	for tag, state := range m.reg().outbounds {
		if _, ok := m.reg().groups[tag]; ok {
			continue
		}
		state.mu.Lock()
		if state.testing || state.queued || state.priorityQueued {
			state.mu.Unlock()
			continue
		}
		if state.invalid || time.Since(state.history.Time) >= m.mainInterval {
			tags = append(tags, tag)
			delays[tag] = state.history.Delay
		}
		state.mu.Unlock()
	}

	return cycleOrder(tags, delays) //H: untested members from the 10th, see cycleOrder
}

func (m *OutboundMonitoring) Touch() {
	if !m.started {
		return
	}
	m.access.Lock()
	defer m.access.Unlock()
	if m.mainTicker != nil {
		m.lastActive.Store(time.Now())
		return
	}
	m.startTimerWorkers()

}

func (m *OutboundMonitoring) emitGroupEvent(groupTags []string) {
	for _, groupTag := range groupTags {
		grp, ok := m.reg().groups[groupTag]
		if !ok || grp.observer == nil {
			continue
		}

		select {
		case grp.notifyCh <- struct{}{}:
		default:
		}
	}
}

func (m *OutboundMonitoring) emitGroupEventThrottled(groupTag string, since time.Time) {
	m.publishGroupEvent(groupTag, since, false)
}

func (m *OutboundMonitoring) emitGroupEventPriority(groupTag string, since time.Time) {
	m.publishGroupEvent(groupTag, since, true)
}

func (m *OutboundMonitoring) publishGroupEvent(groupTag string, since time.Time, priority bool) {
	grp, ok := m.reg().groups[groupTag]
	if !ok || grp.observer == nil {
		return
	}
	tags := make([]string, 0, len(grp.outbounds))
	for tag := range grp.outbounds {
		state := m.reg().outbounds[tag]
		if state == nil {
			continue
		}
		state.mu.Lock()
		if !state.history.Time.Before(since) {
			tags = append(tags, tag)
		}
		state.mu.Unlock()
	}
	grp.observer.Publish(GroupEvent{
		GroupTag: groupTag,
		From:     since,
		To:       time.Now(),
		Priority: priority,
		tags:     tags,
	})
}

// func (m *OutboundMonitoring) OutboundsHistories() map[string]adapter.URLTestHistory {

//		histories := make(map[string]adapter.URLTestHistory)
//		outbounds := m.reg().outbounds
//		for outboundTag, state := range outbounds {
//			state.mu.Lock()
//			histories[outboundTag] = state.history
//			state.mu.Unlock()
//		}
//		return histories
//	}
//
// dependenciesReady reports whether every detour of outbound is usable for a URL test. //H
func (m *OutboundMonitoring) dependenciesReady(state *outboundState) bool {
	if state == nil || len(state.dependencies) == 0 {
		return true
	}
	for _, dep := range state.dependencies {
		if !m.detourReady(state.outbound.Tag(), dep) {
			return false
		}
	}
	return true
}

// detourReady reports whether a test of self through the detour tag measures something: the
// outbound the detour leads to (the selected member, for a group) is connected, has a result of
// this run and is not being tested again. Before that, a test of self fails, or measures the path
// that is about to change, and so does its IP information. //H
func (m *OutboundMonitoring) detourReady(self, tag string) bool {
	reg := m.reg()
	for range 8 { // a group leads to its selected member, which may be a group too
		state, ok := reg.outbounds[tag]
		if !ok || tag == self {
			return true
		}
		grp, isGroup := reg.groups[tag]
		if !isGroup {
			return adapter.IsReady(state.outbound) && state.tested()
		}
		next := RealTag(state.outbound)
		if next == "" || next == tag {
			// nothing selected yet: any member that was tested
			for member := range grp.outbounds {
				if memberState, ok := reg.outbounds[member]; ok && memberState.tested() {
					return true
				}
			}
			return false
		}
		tag = next
	}
	return true
}

// tested reports whether the outbound has a result of this run, and is not being tested again. //H
func (s *outboundState) tested() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.from_cache && s.history.Delay != 0 && !s.testing && !s.queued && !s.priorityQueued
}

// retestDependents tests again the outbounds that dial through tag, also through a group, and
// were tested while tag did not work: their result and IP were measured through a detour that did
// not work. Those not tested yet are tested anyway, once tag has a result. //H
func (m *OutboundMonitoring) retestDependents(tag string, visited map[string]bool) {
	state := m.getState(tag)
	if state == nil || visited[tag] {
		return
	}
	visited[tag] = true
	for _, dependent := range state.dependenciesInverse {
		if _, isGroup := m.reg().groups[dependent]; isGroup {
			if m.groupUses(dependent, tag) { //H: what goes through the group was measured through tag only if it uses tag
				m.retestDependents(dependent, visited)
			} //H
			continue
		}
		dependentState := m.getState(dependent)
		if dependentState == nil {
			continue
		}
		dependentState.mu.Lock()
		tested := !dependentState.from_cache && dependentState.history.Delay != 0
		dependentState.mu.Unlock()
		if tested {
			m.testNow(dependent, true, "measured through "+tag+", which works again") //H
		}
	}
}

func RealTag(detour adapter.Outbound) string {
	if group, isGroup := detour.(adapter.OutboundGroup); isGroup {
		if selected := group.Selected(N.NetworkTCP); selected != nil {
			return selected.Tag()
		}
	}
	return detour.Tag()
}

func (m *OutboundMonitoring) groupNotifierLoop(grp *groupState) {

	defer m.schedulerWG.Done()

	var (
		timer   *time.Timer
		timerCh <-chan time.Time
		since   time.Time
	)

	for {
		select {
		case <-m.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-grp.notifyCh:
			// if !m.cacheDirty.Load() {
			// 	continue
			// }
			if timer == nil {
				timer = time.NewTimer(m.debounceWindow)
				timerCh = timer.C
			}
		case <-timerCh:
			m.emitGroupEventThrottled(grp.tag, since)
			since = time.Now()
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer = nil
			timerCh = nil
		}
	}
}

func (m *OutboundMonitoring) getState(tag string) *outboundState {
	return m.reg().outbounds[tag]
}

type testTask struct {
	settled     atomic.Bool // H: its result is in, or it was given up on; the other of the two is dropped
	staged      bool        // H: asked for by a tap or a selection: tested in stages, see stagedURLTest
	outboundTag string
	cycleID     uint64
	priority    bool
	resultCh    chan<- testOutcome
	waits       int    // H: times it waited for the outbound or its detour to be ready
	reason      string // H: why the test runs, for the MONITORING log
}

type testOutcome struct {
	outboundTag string
	url         string
	history     adapter.URLTestHistory
	err         error
	cycleID     uint64
	priority    bool
}

type outboundState struct {
	mu sync.Mutex

	outbound            adapter.Outbound
	groupTags           []string
	dependenciesInverse []string
	dependencies        []string
	lastURL             string

	invalid        bool
	queued         bool
	priorityQueued bool
	testing        bool
	testDone       chan struct{} // H: closed when the running test is over, see joinRunningTest
	enqueuedCycle  uint64
	from_cache     bool
	// H: history is a staged test's early miss, not a result; confirmed is the last result
	tentative bool
	confirmed adapter.URLTestHistory

	history adapter.URLTestHistory
}

type GroupEvent struct {
	GroupTag string
	From     time.Time
	To       time.Time
	// Priority is set for selection changes so OutboundsInfo can bypass its debounce.
	Priority bool
	tags     []string
}

type groupState struct {
	tag       string
	outbounds map[string]struct{}

	observer  *Broadcaster[GroupEvent]
	notifyCh  chan struct{}
	bestDelay uint16
}

type History struct {
	OutboundData map[string]*adapter.URLTestHistory `json:"outbound_data"`
}

func (m *OutboundMonitoring) saveHistory() error {
	if m.cache == nil {
		return nil
	}
	history := &History{
		OutboundData: make(map[string]*adapter.URLTestHistory),
	}
	for tag, state := range m.reg().outbounds {
		state.mu.Lock()
		h := state.history
		state.mu.Unlock()
		history.OutboundData[tag] = &h
	}
	content, err := json.Marshal(history)
	if err != nil {
		m.logger.Error("failed to marshal outbound monitoring history: ", err)
		return err
	}
	m.cache.SaveBinary("outbound_monitoring_history", &adapter.SavedBinary{
		LastUpdated: time.Now(),
		Content:     content,
	})
	return nil
}
func (m *OutboundMonitoring) loadHistory() *History {
	history := &History{}
	if m.cache == nil {
		return history
	}
	saved := m.cache.LoadBinary("outbound_monitoring_history")
	if saved == nil {
		return history
	}
	err := json.Unmarshal(saved.Content, history)
	if err != nil {
		m.logger.Error("failed to unmarshal outbound monitoring history: ", err)
		return history
	}
	for tag, his := range history.OutboundData {
		if state, ok := m.reg().outbounds[tag]; ok && his != nil {
			if _, ok := m.reg().groups[tag]; ok {
				continue
			}
			// H: a cached timeout stays one, so the cycle tests it last (cycleOrder)
			state.mu.Lock()
			state.history = *his
			state.history.IpInfoFromCache = his.IpInfo != nil //H
			state.history.IPv6FromCache = his.IPv6 != nil     //H
			state.from_cache = true
			state.mu.Unlock()
		}
	}
	return history
}

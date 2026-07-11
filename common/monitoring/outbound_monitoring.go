package monitoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
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
	currentLinkIndex atomic.Uint32
	access           sync.Mutex
	idleTimeout      time.Duration
	lastActive       common.TypedValue[time.Time]
	workersRunning   atomic.Bool
	mainInterval     time.Duration
	debounceWindow   time.Duration
	urlTestTimeout   time.Duration
	workersCount     int
	history          adapter.URLTestHistoryStorage

	mainTicker *time.Ticker

	priorityQueue chan *testTask
	normalQueue   chan *testTask

	outbounds map[string]*outboundState
	groups    map[string]*groupState

	cacheDirty atomic.Bool

	cycleSeq     uint64
	cycleRunning atomic.Bool

	workerWG    sync.WaitGroup
	schedulerWG sync.WaitGroup
	closerOnce  sync.Once
}

// InterfaceUpdated implements [adapter.InterfaceUpdateListener].
func (m *OutboundMonitoring) InterfaceUpdated() {
	m.startCycleOnce()
}

// Name implements [adapter.LifecycleService].
func (m *OutboundMonitoring) Name() string {
	return "outbound-monitoring"
}

func (m *OutboundMonitoring) OutboundsHistory(groupTag string) map[string]*adapter.URLTestHistory {

	histories := make(map[string]*adapter.URLTestHistory)

	grp, ok := m.groups[groupTag]
	if !ok {
		return histories
	}
	//m.logger.Debug("collecting history for group ", groupTag, " with ", len(grp.outbounds), " outbounds")
	for outboundTag := range grp.outbounds {
		histories[outboundTag] = m.getUrlTest(outboundTag)
		// m.logger.Error("checking history for outbound ", outboundTag)

	}
	return histories
}

func (m *OutboundMonitoring) getUrlTest(outboundTag string) *adapter.URLTestHistory {
	state, ok := m.outbounds[outboundTag]
	if !ok {
		return nil
	}

	if grp, ok := m.groups[outboundTag]; ok {
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
	grp, ok := m.groups[groupTag]
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
				minHis.IpInfo = his.IpInfo
			} else if minHis.IpInfo == nil {
				minHis.IpInfo = his.IpInfo
			}
		} else {
			if minHisFromCache == nil {
				minHisFromCache = his
			} else if his.Delay < minHisFromCache.Delay {
				minHisFromCache.Delay = his.Delay
				minHisFromCache.IpInfo = his.IpInfo
			} else if minHisFromCache.IpInfo == nil {
				minHisFromCache.IpInfo = his.IpInfo
			}
		}
	}

	final := minHis
	if minHis == nil || minHis.Delay >= TimeoutDelay {
		final = minHisFromCache
	} else if minHisFromCache != nil && minHis.IpInfo == nil {
		final.IpInfo = minHisFromCache.IpInfo
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

func (noopFlowTracker) AttachFlow(tun.FlowHandle)          {}
func (noopFlowTracker) CountForward(int)                   {}
func (noopFlowTracker) CountReverse(int)                   {}
func (noopFlowTracker) FlowEstablished()                   {}
func (noopFlowTracker) CloseFlow(tun.FlowCloseReason)       {}

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

		priorityQueue: make(chan *testTask, 1000),
		normalQueue:   make(chan *testTask, 10000),
		outbounds:     make(map[string]*outboundState),
		groups:        make(map[string]*groupState),
	}

	return m, nil
}

func (m *OutboundMonitoring) Start(stage adapter.StartStage) error {
	m.logger.Info("starting outbound monitoring ", stage)
	switch stage {
	case adapter.StartStateInitialize:
		m.cache = service.FromContext[adapter.CacheFile](m.ctx)

		for _, outbound := range m.outboundManager.Outbounds() {
			// if _, ok := outbound.(adapter.OutboundGroup); !ok {
			m.outbounds[outbound.Tag()] = &outboundState{groupTags: []string{}, invalid: true, outbound: outbound, dependencies: outbound.Dependencies()}
			// }
			//m.logger.Info("registered outbound for monitoring: ", outbound.Tag())
		}
		for _, outbound := range m.endpointManager.Endpoints() {
			// if _, ok := outbound.(adapter.OutboundGroup); !ok {
			m.outbounds[outbound.Tag()] = &outboundState{groupTags: []string{}, invalid: true, outbound: outbound, dependencies: outbound.Dependencies()}
			// }
			//m.logger.Info("registered outbound for monitoring: ", outbound.Tag())
		}
		for tag, outbound := range m.outbounds {
			for _, dep := range outbound.dependencies {
				m.outbounds[dep].dependenciesInverse = append(m.outbounds[dep].dependenciesInverse, tag)
			}
		}

		m.logger.Info("registered ", len(m.outbounds), " outbounds for monitoring")
		grp := m.makeGroup("")
		for tag := range m.outbounds {
			grp.outbounds[tag] = struct{}{}
			m.outbounds[tag].groupTags = append(m.outbounds[tag].groupTags, "")
		}
		for _, outbound := range m.outboundManager.Outbounds() {
			if og, ok := outbound.(adapter.OutboundGroup); ok {
				groupTag := og.Tag()
				grp := m.makeGroup(groupTag)
				for _, tag := range og.All() {
					if _, exists := m.outbounds[tag]; !exists {
						return errors.New("outbound monitoring: outbound not found: " + tag + " in group " + groupTag)
					}
					grp.outbounds[tag] = struct{}{}
					m.outbounds[tag].groupTags = append(m.outbounds[tag].groupTags, groupTag)
				}

				//m.logger.Info("registered outbound group for monitoring: ", groupTag, " with ", len(og.All()), " outbounds")

			}
		}
		m.logger.Info("registered ", len(m.groups), " outbound groups for monitoring")
		m.loadHistory()
	case adapter.StartStatePostStart:
		for i := 0; i < m.workersCount; i++ {
			m.workerWG.Add(1)
			go m.workerLoop()
		}
		for groupTag := range m.groups {
			m.schedulerWG.Add(1)
			go m.groupNotifierLoop(m.groups[groupTag])
		}

		m.started = true
		m.Touch()
	}

	return nil
}

func (m *OutboundMonitoring) startTimerWorkers() {
	if !m.workersRunning.CompareAndSwap(false, true) {
		return
	}
	m.mainTicker = time.NewTicker(m.mainInterval)

	m.pauseCallback = pause.RegisterTicker(m.pause, m.mainTicker, m.mainInterval, nil)
	m.schedulerWG.Add(1)
	go m.scheduleLoop()
}
func (m *OutboundMonitoring) stopTimerWorkers() {
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

func (m *OutboundMonitoring) SignalChange(outboundTag string) error {
	if grp, ok := m.groups[outboundTag]; ok {
		grp.notifyCh <- struct{}{}
		return nil
	}
	state := m.getState(outboundTag)
	if state == nil {
		return errors.New("outbound not registered")
	}
	for _, groupTag := range state.groupTags {
		if grp, ok := m.groups[groupTag]; ok {
			grp.notifyCh <- struct{}{}
		}
	}
	return nil

}
func (m *OutboundMonitoring) TestNow(outboundTag string) error {
	m.testParents(outboundTag, true)
	return m.testNow(outboundTag, true)
}
func (m *OutboundMonitoring) testNow(outboundTag string, priority bool) error {
	m.logger.Info("testing outbound ", outboundTag, " with priority: ", priority)
	if grp, ok := m.groups[outboundTag]; ok {
		for tag := range grp.outbounds {
			m.testNow(tag, false)
		}
	} else {
		state := m.getState(outboundTag)
		if state == nil {
			return errors.New("outbound not registered")
		}

		task := &testTask{
			outboundTag: outboundTag,
			cycleID:     m.cycleSeq,
			priority:    priority,
		}

		if !m.enqueueTask(task) {
			// return errors.New("test already queued")
		}
	}
	return nil
}

func (m *OutboundMonitoring) testParents(outboundTag string, first bool) {
	state := m.getState(outboundTag)
	if state == nil {
		return
	}
	if _, ok := m.groups[outboundTag]; !ok && !first {
		m.logger.Info("testing outbound ", outboundTag)
		m.testNow(outboundTag, true)
	}
	for _, dep := range state.dependenciesInverse {
		m.logger.Info("testing parent outbound ", dep, " of ", outboundTag)
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
		cycleID:     m.cycleSeq,
		priority:    true,
	})

	return nil
}

func (m *OutboundMonitoring) SubscribeGroup(groupTag string) (observer <-chan GroupEvent, err error) {

	if g, ok := m.groups[groupTag]; ok {
		return g.observer.Subscribe(1), nil
	}
	return nil, E.New("group not found ", groupTag)
}
func (m *OutboundMonitoring) UnsubscribeGroup(groupTag string, observer <-chan GroupEvent) (err error) {
	if g, ok := m.groups[groupTag]; ok {
		g.observer.Unsubscribe(observer)
		return nil
	}
	return E.New("group not found ", groupTag)
}

func (m *OutboundMonitoring) Close() error {
	m.closerOnce.Do(func() {
		m.stopTimerWorkers()

		// close(m.priorityQueue)
		// close(m.normalQueue)
		for _, g := range m.groups {
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

func (m *OutboundMonitoring) scheduleLoop() {
	m.logger.Info("outbound monitoring schedule loop started")
	m.startCycleOnce()
	ticker := m.mainTicker
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
			m.startCycleOnce()
		}
	}
}

func (m *OutboundMonitoring) workerLoop() {

	defer m.workerWG.Done()
	for {

		select {
		case <-m.ctx.Done():
			return
		case task := <-m.priorityQueue:
			m.executeTask(task) //for prioritising tasks, we execute them immediately
		default:
			select {
			case <-m.ctx.Done():
				return
			case task := <-m.priorityQueue:
				m.executeTask(task)
			case task := <-m.normalQueue:
				m.executeTask(task)
			}
		}
	}
}

func (m *OutboundMonitoring) executeTask(task *testTask) {
	select {
	case <-m.ctx.Done():
		return
	default:
	}

	state := m.outbounds[task.outboundTag]
	if state == nil {
		return
	}

	state.mu.Lock()
	state.testing = true
	state.mu.Unlock()
	defer func() {
		state.mu.Lock()
		state.testing = false
		state.mu.Unlock()
	}()
	state.mu.Lock()
	cycle := task.cycleID
	state.mu.Unlock()

	if cycle < 10 && !state.outbound.IsReady() {
		m.logger.Info("outbound ", task.outboundTag, " is not ready, skipping test")
		go func() {
			select {
			case <-m.ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			state.mu.Lock()
			task.cycleID++
			state.mu.Unlock()
			m.enqueueTask(task)
		}()
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		delay, err := m.tester(m.ctx, task.outboundTag)

		outcome := testOutcome{
			outboundTag: task.outboundTag,
			history:     delay,
			err:         err,
			cycleID:     task.cycleID,
			priority:    task.priority,
		}

		m.applyResult(outcome)
		if task.resultCh != nil {
			select {
			case task.resultCh <- outcome:
			case <-m.ctx.Done():
			default:
			}

		}
	}()
	select {
	case <-m.ctx.Done():
		return
	case <-done:
	}

}

func (m *OutboundMonitoring) tester(parent context.Context, tag string) (adapter.URLTestHistory, error) {
	out, ok := m.outbounds[tag]
	if !ok {
		return adapter.URLTestHistory{Delay: 0}, errors.New("outbound not registered")
	}

	idx := m.currentLinkIndex.Load()

	ctx, cancel := context.WithTimeout(parent, m.urlTestTimeout)
	defer cancel()

	delay, err := urltest.URLTest(ctx, m.urls[idx], out.outbound)

	his := adapter.URLTestHistory{
		Time:  time.Now(),
		Delay: delay,
	}
	if err != nil || delay >= TimeoutDelay {
		his.Delay = TimeoutDelay
		m.logger.Warn("outbound ", tag, " URL test failed: ", err)
		return his, err
	}
	select {
	case <-parent.Done():
		return his, parent.Err()
	default:
	}
	if out.history.IpInfo == nil || out.from_cache {

		ctx, cancel2 := context.WithTimeout(parent, m.urlTestTimeout)
		defer cancel2()

		newip, t, err := ipinfo.GetIpInfo(m.logger, ctx, out.outbound)
		if err == nil {
			his.IpInfo = mergeIpInfo(out.history.IpInfo, newip)
			if t < his.Delay {
				his.Delay = t
			}
		}
	}
	if his.IpInfo != nil {
		m.logger.Info("outbound ", tag, " IP ", fmt.Sprint(his.IpInfo), " (", his.Delay, "ms): ", err)
	} else {
		m.logger.Info("outbound ", tag, " , IP: -          (", his.Delay, "ms)")
	}
	return his, nil
}

func (m *OutboundMonitoring) startCycleOnce() bool {
	if !m.cycleRunning.CompareAndSwap(false, true) {
		return false
	}
	go func() {
		defer m.cycleRunning.Store(false)
		m.logger.Info("starting regular outbound monitoring cycle")
		m.runCycle()
	}()
	return true
}

func (m *OutboundMonitoring) runCycle() {
	cycleID := atomic.AddUint64(&m.cycleSeq, 1)
	tags := m.collectCycleTargets()

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
	state, ok := m.outbounds[task.outboundTag]
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
		select {
		case m.priorityQueue <- task:
			return true
		default:
			return false
		}

	} else {
		select {
		case m.normalQueue <- task:
			return true
		default:
			return false
		}
	}

}

func (m *OutboundMonitoring) applyResult(outcome testOutcome) *adapter.URLTestHistory {
	select {
	case <-m.ctx.Done():
		return nil
	default:
	}
	state, ok := m.outbounds[outcome.outboundTag]
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
	state.from_cache = false
	if outcome.history.IpInfo != nil {
		state.history.IpInfo = outcome.history.IpInfo
	}
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

	tags := make([]string, 0, len(m.outbounds))

	delays := make(map[string]uint16, len(tags))

	for tag, state := range m.outbounds {
		if _, ok := m.groups[tag]; ok {
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

	sort.SliceStable(tags, func(i, j int) bool {
		return delays[tags[i]] < delays[tags[j]]
	})
	return tags
}

func (m *OutboundMonitoring) makeGroup(tag string) *groupState {
	grp, ok := m.groups[tag]
	if ok {
		return grp
	}

	grp = &groupState{
		tag:       tag,
		outbounds: make(map[string]struct{}),
		observer:  NewBroadcaster[GroupEvent](m.ctx),
		notifyCh:  make(chan struct{}, 1),
	}
	m.groups[tag] = grp
	return grp
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
		grp, ok := m.groups[groupTag]
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

	grp, ok := m.groups[groupTag]
	if !ok || grp.observer == nil {
		return
	}
	tags := make([]string, 0, len(grp.outbounds))
	for tag := range grp.outbounds {
		state := m.outbounds[tag]
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
		tags:     tags,
	})
}

// func (m *OutboundMonitoring) OutboundsHistories() map[string]adapter.URLTestHistory {

//		histories := make(map[string]adapter.URLTestHistory)
//		outbounds := m.outbounds
//		for outboundTag, state := range outbounds {
//			state.mu.Lock()
//			histories[outboundTag] = state.history
//			state.mu.Unlock()
//		}
//		return histories
//	}
func RealTag(detour adapter.Outbound) string {
	if group, isGroup := detour.(adapter.OutboundGroup); isGroup {
		tag := group.Now()
		if tag != "" {
			return tag
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
	return m.outbounds[tag]
}

type testTask struct {
	outboundTag string
	cycleID     uint64
	priority    bool
	resultCh    chan<- testOutcome
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
	enqueuedCycle  uint64
	from_cache     bool

	history adapter.URLTestHistory
}

type GroupEvent struct {
	GroupTag string
	From     time.Time
	To       time.Time
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
	for tag, state := range m.outbounds {
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
		if state, ok := m.outbounds[tag]; ok && his != nil {
			if _, ok := m.groups[tag]; ok {
				continue
			}
			if his.Delay >= TimeoutDelay {
				his.Delay = 0
			}
			state.mu.Lock()
			state.history = *his
			state.from_cache = true
			state.mu.Unlock()
		}
	}
	return history
}

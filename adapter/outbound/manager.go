package outbound

import (
	"context"
	"os"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.OutboundManager = (*Manager)(nil)

type Manager struct {
	registry                adapter.OutboundRegistry
	endpoint                adapter.EndpointManager
	defaultTag              string
	access                  sync.RWMutex
	startAccess             sync.Mutex
	scope                   *adapter.Scope
	stage                   adapter.StartStage
	outbounds               []adapter.Outbound
	outboundByTag           map[string]adapter.Outbound
	dependByTag             map[string][]string
	defaultOutbound         adapter.Outbound
	defaultOutboundFallback func() (adapter.Outbound, error)
}

func NewManager(registry adapter.OutboundRegistry, endpoint adapter.EndpointManager, defaultTag string) *Manager {
	return &Manager{
		registry:      registry,
		endpoint:      endpoint,
		defaultTag:    defaultTag,
		outboundByTag: make(map[string]adapter.Outbound),
		dependByTag:   make(map[string][]string),
	}
}

func (m *Manager) Initialize(defaultOutboundFallback func() (adapter.Outbound, error)) {
	m.defaultOutboundFallback = defaultOutboundFallback
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.startAccess.Lock()
	defer m.startAccess.Unlock()
	m.access.Lock()
	m.scope = scope
	m.stage = stage
	if stage == adapter.StartStateInitialize {
		if m.defaultTag != "" && m.defaultOutbound == nil {
			defaultEndpoint, loaded := m.endpoint.Get(m.defaultTag)
			if !loaded {
				m.access.Unlock()
				return E.New("default outbound not found: ", m.defaultTag)
			}
			m.defaultOutbound = defaultEndpoint
		}
		if m.defaultOutbound == nil {
			directOutbound, err := m.defaultOutboundFallback()
			if err != nil {
				m.access.Unlock()
				return E.Cause(err, "create direct outbound for fallback")
			}
			m.outbounds = append(m.outbounds, directOutbound)
			m.outboundByTag[directOutbound.Tag()] = directOutbound
			m.defaultOutbound = directOutbound
		}
	}
	outbounds := m.outbounds
	m.access.Unlock()
	if stage == adapter.StartStateStart {
		return m.startOutbounds(scope, append(outbounds, common.Map(m.endpoint.Endpoints(), func(it adapter.Endpoint) adapter.Outbound { return it })...))
	}
	for _, outbound := range outbounds {
		lifecycle, isLifecycle := outbound.(adapter.Lifecycle)
		if !isLifecycle {
			continue
		}
		name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
		err := scope.Start(name, lifecycle, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) startOutbounds(scope *adapter.Scope, outbounds []adapter.Outbound) error {
	started := make(map[string]bool)
	for {
		canContinue := false
	startOne:
		for _, outboundToStart := range outbounds {
			outboundTag := outboundToStart.Tag()
			if started[outboundTag] {
				continue
			}
			dependencies := outboundToStart.Dependencies()
			for _, dependency := range dependencies {
				if !started[dependency] {
					continue startOne
				}
			}
			started[outboundTag] = true
			canContinue = true
			if endpoint, isEndpoint := outboundToStart.(adapter.Endpoint); isEndpoint {
				err := m.endpoint.StartEndpoint(endpoint)
				if err != nil {
					return err
				}
				continue
			}
			lifecycle, isLifecycle := outboundToStart.(adapter.Lifecycle)
			if !isLifecycle {
				continue
			}
			name := "outbound/" + outboundToStart.Type() + "[" + outboundTag + "]"
			err := scope.Start(name, lifecycle, adapter.StartStateStart)
			if err != nil {
				return err
			}
		}
		if len(started) == len(outbounds) {
			break
		}
		if canContinue {
			continue
		}
		currentOutbound := common.Find(outbounds, func(it adapter.Outbound) bool {
			return !started[it.Tag()]
		})
		var lintOutbound func(oTree []string, oCurrent adapter.Outbound) error
		lintOutbound = func(oTree []string, oCurrent adapter.Outbound) error {
			problemOutboundTag := common.Find(oCurrent.Dependencies(), func(it string) bool {
				return !started[it]
			})
			if common.Contains(oTree, problemOutboundTag) {
				return E.New("circular outbound dependency: ", strings.Join(oTree, " -> "), " -> ", problemOutboundTag)
			}
			problemOutbound := common.Find(outbounds, func(it adapter.Outbound) bool {
				return it.Tag() == problemOutboundTag
			})
			if problemOutbound == nil {
				return E.New("dependency[", problemOutboundTag, "] not found for outbound[", oCurrent.Tag(), "]")
			}
			return lintOutbound(append(oTree, problemOutboundTag), problemOutbound)
		}
		return lintOutbound([]string{currentOutbound.Tag()}, currentOutbound)
	}
	return nil
}

func (m *Manager) Outbounds() []adapter.Outbound {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.outbounds
}

func (m *Manager) Outbound(tag string) (adapter.Outbound, bool) {
	m.access.RLock()
	outbound, found := m.outboundByTag[tag]
	m.access.RUnlock()
	if found {
		return outbound, true
	}
	return m.endpoint.Get(tag)
}

func (m *Manager) Default() adapter.Outbound {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.defaultOutbound
}

func (m *Manager) Remove(tag string) error {
	m.startAccess.Lock()
	defer m.startAccess.Unlock()
	m.access.Lock()
	outbound, found := m.outboundByTag[tag]
	if !found {
		m.access.Unlock()
		return os.ErrInvalid
	}
	dependBy := m.dependByTag[tag]
	if len(dependBy) > 0 {
		m.access.Unlock()
		return E.New("outbound[", tag, "] is depended by ", strings.Join(dependBy, ", "))
	}
	delete(m.outboundByTag, tag)
	m.outbounds = common.Filter(m.outbounds, func(it adapter.Outbound) bool {
		return it != outbound
	})
	m.removeDependencies(outbound)
	if m.defaultOutbound == outbound {
		if len(m.outbounds) > 0 {
			m.defaultOutbound = m.outbounds[0]
		} else {
			m.defaultOutbound = nil
		}
	}
	scope := m.scope
	m.access.Unlock()
	lifecycle, isLifecycle := outbound.(adapter.Lifecycle)
	if scope == nil || !isLifecycle {
		return nil
	}
	return scope.Remove(lifecycle)
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, inboundType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}
	outbound, err := m.registry.CreateOutbound(ctx, router, logger, tag, inboundType, options)
	if err != nil {
		return err
	}
	m.startAccess.Lock()
	defer m.startAccess.Unlock()
	m.access.RLock()
	scope := m.scope
	stage := m.stage
	m.access.RUnlock()
	lifecycle, isLifecycle := outbound.(adapter.Lifecycle)
	if scope != nil && isLifecycle {
		name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
		for _, startStage := range adapter.ListStartStages[:stage+1] {
			err = scope.Start(name, lifecycle, startStage)
			if err != nil {
				return E.Errors(err, scope.Remove(lifecycle))
			}
		}
	}
	m.access.Lock()
	existsOutbound, loaded := m.outboundByTag[tag]
	if loaded {
		m.outbounds = common.Filter(m.outbounds, func(it adapter.Outbound) bool {
			return it != existsOutbound
		})
		m.removeDependencies(existsOutbound)
	}
	m.outbounds = append(m.outbounds, outbound)
	m.outboundByTag[tag] = outbound
	for _, dependency := range outbound.Dependencies() {
		m.dependByTag[dependency] = append(m.dependByTag[dependency], tag)
	}
	if tag == m.defaultTag || (m.defaultTag == "" && m.defaultOutbound == nil) || (loaded && m.defaultOutbound == existsOutbound) {
		m.defaultOutbound = outbound
	}
	m.access.Unlock()
	if !loaded || scope == nil {
		return nil
	}
	existsLifecycle, isExistsLifecycle := existsOutbound.(adapter.Lifecycle)
	if !isExistsLifecycle {
		return nil
	}
	err = scope.Remove(existsLifecycle)
	if err != nil {
		return E.Cause(err, "close outbound/", existsOutbound.Type(), "[", existsOutbound.Tag(), "]")
	}
	return nil
}

func (m *Manager) removeDependencies(outbound adapter.Outbound) {
	tag := outbound.Tag()
	for _, dependency := range outbound.Dependencies() {
		dependBy := common.Filter(m.dependByTag[dependency], func(it string) bool {
			return it != tag
		})
		if len(dependBy) == 0 {
			delete(m.dependByTag, dependency)
		} else {
			m.dependByTag[dependency] = dependBy
		}
	}
}

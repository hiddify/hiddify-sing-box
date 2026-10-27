package outbound

import (
	"context"
	"github.com/sagernet/sing-box/option"
	"os"
	"slices"
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
	outbounds               []adapter.Outbound
	outboundByTag           map[string]adapter.Outbound
	defaultOutbound         adapter.Outbound
	defaultOutboundFallback func() (adapter.Outbound, error)
	scope                   *adapter.Scope // H: where outbounds created by hot reload are started
	started                 bool
}

func NewManager(registry adapter.OutboundRegistry, endpoint adapter.EndpointManager, defaultTag string) *Manager {
	return &Manager{
		registry:      registry,
		endpoint:      endpoint,
		defaultTag:    defaultTag,
		outboundByTag: make(map[string]adapter.Outbound),
	}
}

func (m *Manager) Initialize(defaultOutboundFallback func() (adapter.Outbound, error)) {
	m.defaultOutboundFallback = defaultOutboundFallback
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.access.Lock()
	m.scope = scope
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
		lifecycle, isLifecycle := adapter.AsLifecycle(outbound) // H: also closes outbounds that only have Close
		if !isLifecycle {
			continue
		}
		name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
		err := scope.Start(name, lifecycle, stage)
		if err != nil {
			return err
		}
	}
	if stage == adapter.StartStateStarted {
		m.access.Lock()
		m.started = true
		m.access.Unlock()
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
			lifecycle, isLifecycle := adapter.AsLifecycle(outboundToStart) // H
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
	return m.remove(tag, false)
}

// RemoveForReload removes an outbound even while others still depend on it; used by hot reload,
// which recreates those dependents in the same reload. //H
func (m *Manager) RemoveForReload(tag string) error {
	return m.remove(tag, true)
}

func (m *Manager) remove(tag string, ignoreDependents bool) error {
	m.access.Lock()
	outbound, found := m.outboundByTag[tag]
	if !found {
		m.access.Unlock()
		return os.ErrInvalid
	}
	if !ignoreDependents {
		dependBy := m.dependents(tag)
		if len(dependBy) > 0 {
			m.access.Unlock()
			return E.New("outbound[", tag, "] is depended by ", strings.Join(dependBy, ", "))
		}
	}
	delete(m.outboundByTag, tag)
	index := slices.Index(m.outbounds, outbound)
	if index == -1 {
		panic("invalid outbound index")
	}
	m.outbounds = slices.Delete(slices.Clone(m.outbounds), index, index+1) // H: never change a slice already handed out
	if m.defaultOutbound == outbound {
		if len(m.outbounds) > 0 {
			m.defaultOutbound = m.outbounds[0]
		} else {
			m.defaultOutbound = nil
		}
	}
	started := m.started
	m.access.Unlock()
	if started {
		return adapter.CloseLate(m.scope, outbound)
	}
	return nil
}

// dependents lists the outbounds and endpoints that depend on tag. Call with access held.
func (m *Manager) dependents(tag string) []string {
	var dependBy []string
	for _, outbound := range m.outbounds {
		if common.Contains(outbound.Dependencies(), tag) {
			dependBy = append(dependBy, outbound.Tag())
		}
	}
	for _, endpoint := range m.endpoint.Endpoints() {
		if common.Contains(endpoint.Dependencies(), tag) {
			dependBy = append(dependBy, endpoint.Tag())
		}
	}
	return dependBy
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, inboundType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}
	option.MigrateTLSFragment(options) //H: a tls_fragment in the tls block applies like the dialer's
	outbound, err := m.registry.CreateOutbound(ctx, router, logger, tag, inboundType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	started := m.started
	m.access.Unlock()
	if started { // H: hot reload; started outside the lock, as starting may look up other outbounds
		err = adapter.StartLate(m.scope, "outbound/"+outbound.Type()+"["+outbound.Tag()+"]", outbound)
		if err != nil {
			return err
		}
	}
	m.access.Lock()
	existsOutbound, replaced := m.outboundByTag[tag]
	if replaced && !started {
		m.access.Unlock()
		return E.New("duplicate outbound tag: ", tag)
	}
	if replaced {
		existsIndex := slices.Index(m.outbounds, existsOutbound)
		if existsIndex == -1 {
			panic("invalid outbound index")
		}
		// H: the replacement takes the old one's place (callers rely on the order, e.g. the main group
		// comes first); a copy, so a slice already handed out never changes
		m.outbounds = slices.Clone(m.outbounds)
		m.outbounds[existsIndex] = outbound
	} else {
		m.outbounds = append(m.outbounds, outbound)
	}
	m.outboundByTag[tag] = outbound
	if tag == m.defaultTag || (m.defaultTag == "" && m.defaultOutbound == nil) || m.defaultOutbound == existsOutbound && replaced {
		m.defaultOutbound = outbound
	}
	m.access.Unlock()
	if replaced {
		err = adapter.CloseLate(m.scope, existsOutbound)
		if err != nil {
			return E.Cause(err, "close outbound/", existsOutbound.Type(), "[", existsOutbound.Tag(), "]")
		}
	}
	return nil
}

// SetDefaultTag changes the default outbound (route.final); used by hot reload. //H
func (m *Manager) SetDefaultTag(tag string) error {
	m.access.Lock()
	m.defaultTag = tag
	if tag == "" {
		m.access.Unlock()
		return nil
	}
	outbound, loaded := m.outboundByTag[tag]
	m.access.Unlock()
	if !loaded {
		endpoint, endpointLoaded := m.endpoint.Get(tag)
		if !endpointLoaded {
			return E.New("default outbound not found: ", tag)
		}
		outbound = endpoint
	}
	m.access.Lock()
	m.defaultOutbound = outbound
	m.access.Unlock()
	return nil
}

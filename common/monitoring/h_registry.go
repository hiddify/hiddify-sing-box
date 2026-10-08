package monitoring

import (
	"errors"

	"github.com/sagernet/sing-box/adapter"
)

// monitoringRegistry is the set of monitored outbounds and groups. It is never modified once
// stored: Reload builds a new one, so readers need no lock.
type monitoringRegistry struct {
	outbounds map[string]*outboundState
	groups    map[string]*groupState
}

func newMonitoringRegistry() *monitoringRegistry {
	return &monitoringRegistry{
		outbounds: make(map[string]*outboundState),
		groups:    make(map[string]*groupState),
	}
}

func (m *OutboundMonitoring) reg() *monitoringRegistry {
	return m.registry.Load()
}

// buildRegistry reads the current outbounds, endpoints and groups. An outbound that is still the
// same instance keeps its test history from previous; a group that still exists keeps its
// observer, so subscribers keep receiving its events.
func (m *OutboundMonitoring) buildRegistry(previous *monitoringRegistry) (*monitoringRegistry, error) {
	registry := newMonitoringRegistry()
	add := func(outbound adapter.Outbound) {
		state := &outboundState{groupTags: []string{}, invalid: true, outbound: outbound, dependencies: outbound.Dependencies()}
		if old, ok := previous.outbounds[outbound.Tag()]; ok && old.outbound == outbound {
			old.mu.Lock()
			state.history = old.history
			state.lastURL = old.lastURL
			state.invalid = old.invalid
			state.from_cache = old.from_cache
			old.mu.Unlock()
		}
		registry.outbounds[outbound.Tag()] = state
	}
	for _, outbound := range m.outboundManager.Outbounds() {
		add(outbound)
	}
	for _, endpoint := range m.endpointManager.Endpoints() {
		add(endpoint)
	}
	for tag, state := range registry.outbounds {
		for _, dependency := range state.dependencies {
			if dependencyState, ok := registry.outbounds[dependency]; ok {
				dependencyState.dependenciesInverse = append(dependencyState.dependenciesInverse, tag)
			}
		}
	}

	all := m.registryGroup(registry, previous, "")
	for tag, state := range registry.outbounds {
		all.outbounds[tag] = struct{}{}
		state.groupTags = append(state.groupTags, "")
	}
	for _, outbound := range m.outboundManager.Outbounds() {
		group, isGroup := outbound.(adapter.OutboundGroup)
		if !isGroup {
			continue
		}
		groupTag := group.Tag()
		grp := m.registryGroup(registry, previous, groupTag)
		for _, tag := range group.All() {
			state, exists := registry.outbounds[tag]
			if !exists {
				return nil, errors.New("outbound monitoring: outbound not found: " + tag + " in group " + groupTag)
			}
			grp.outbounds[tag] = struct{}{}
			state.groupTags = append(state.groupTags, groupTag)
		}
	}
	return registry, nil
}

func (m *OutboundMonitoring) registryGroup(registry, previous *monitoringRegistry, tag string) *groupState {
	if grp, ok := registry.groups[tag]; ok {
		return grp
	}
	grp := &groupState{tag: tag, outbounds: make(map[string]struct{})}
	if old, ok := previous.groups[tag]; ok {
		grp.observer = old.observer
		grp.notifyCh = old.notifyCh
		grp.bestDelay = old.bestDelay
	} else {
		grp.observer = NewBroadcaster[GroupEvent](m.ctx)
		grp.notifyCh = make(chan struct{}, 1)
	}
	registry.groups[tag] = grp
	return grp
}

// Reload re-reads the outbounds and endpoints after they were replaced at runtime (hot reload).
// New and replaced outbounds are tested; groups that no longer exist close their subscriptions.
func (m *OutboundMonitoring) Reload() error {
	m.reloadAccess.Lock()
	defer m.reloadAccess.Unlock()
	previous := m.reg()
	registry, err := m.buildRegistry(previous)
	if err != nil {
		return err
	}
	m.registry.Store(registry)
	if m.started {
		for tag, grp := range registry.groups {
			if _, existed := previous.groups[tag]; !existed {
				m.schedulerWG.Add(1)
				go m.groupNotifierLoop(grp)
			}
		}
	}
	for tag, grp := range previous.groups {
		if _, kept := registry.groups[tag]; !kept && grp.observer != nil {
			grp.observer.Close()
		}
	}
	m.logger.Info("reloaded ", len(registry.outbounds), " outbounds and ", len(registry.groups), " groups for monitoring")
	if m.started {
		groupTags := make([]string, 0, len(registry.groups))
		for tag := range registry.groups {
			groupTags = append(groupTags, tag)
		}
		m.emitGroupEvent(groupTags)
		m.startCycleOnce()
	}
	return nil
}

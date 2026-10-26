package inbound

import (
	"context"
	"os"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.InboundManager = (*Manager)(nil)

type Manager struct {
	registry     adapter.InboundRegistry
	endpoint     adapter.EndpointManager
	access       sync.Mutex
	scope        *adapter.Scope // H: where inbounds created by hot reload are started
	started      bool
	inbounds     []adapter.Inbound
	inboundByTag map[string]adapter.Inbound
}

func NewManager(registry adapter.InboundRegistry, endpoint adapter.EndpointManager) *Manager {
	return &Manager{
		registry:     registry,
		endpoint:     endpoint,
		inboundByTag: make(map[string]adapter.Inbound),
	}
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.access.Lock()
	m.scope = scope
	inbounds := m.inbounds
	m.access.Unlock()
	for _, inbound := range inbounds {
		name := "inbound/" + inbound.Type() + "[" + inbound.Tag() + "]"
		err := scope.Start(name, inbound, stage)
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

func (m *Manager) Inbounds() []adapter.Inbound {
	m.access.Lock()
	defer m.access.Unlock()
	return m.inbounds
}

func (m *Manager) Get(tag string) (adapter.Inbound, bool) {
	m.access.Lock()
	inbound, found := m.inboundByTag[tag]
	m.access.Unlock()
	if found {
		return inbound, true
	}
	return m.endpoint.Get(tag)
}

// Remove removes and closes an inbound; used by hot reload. //H
func (m *Manager) Remove(tag string) error {
	m.access.Lock()
	inbound, found := m.inboundByTag[tag]
	if !found {
		m.access.Unlock()
		return os.ErrInvalid
	}
	delete(m.inboundByTag, tag)
	index := slices.Index(m.inbounds, inbound)
	if index == -1 {
		panic("invalid inbound index")
	}
	m.inbounds = slices.Delete(slices.Clone(m.inbounds), index, index+1) // H: never change a slice already handed out
	started := m.started
	m.access.Unlock()
	if started {
		return adapter.CloseLate(m.scope, inbound)
	}
	return nil
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) error {
	inbound, err := m.registry.Create(ctx, router, logger, tag, outboundType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	started := m.started
	m.access.Unlock()
	if started { // H: hot reload
		err = adapter.StartLate(m.scope, "inbound/"+inbound.Type()+"["+inbound.Tag()+"]", inbound)
		if err != nil {
			return err
		}
	}
	m.access.Lock()
	existsInbound, replaced := m.inboundByTag[tag]
	if replaced && !started {
		m.access.Unlock()
		return E.New("duplicate inbound tag: ", tag)
	}
	if replaced {
		existsIndex := slices.Index(m.inbounds, existsInbound)
		if existsIndex == -1 {
			panic("invalid inbound index")
		}
		m.inbounds = slices.Delete(slices.Clone(m.inbounds), existsIndex, existsIndex+1) // H: never change a slice already handed out
	}
	m.inbounds = append(m.inbounds, inbound)
	m.inboundByTag[tag] = inbound
	m.access.Unlock()
	if replaced {
		err = adapter.CloseLate(m.scope, existsInbound)
		if err != nil {
			return E.Cause(err, "close inbound/", existsInbound.Type(), "[", existsInbound.Tag(), "]")
		}
	}
	return nil
}

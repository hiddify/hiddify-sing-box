package endpoint

import (
	"context"
	"os"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.EndpointManager = (*Manager)(nil)

type Manager struct {
	registry      adapter.EndpointRegistry
	access        sync.Mutex
	scope         *adapter.Scope
	started       bool // H: components created from now on are started right away (hot reload)
	endpoints     []adapter.Endpoint
	endpointByTag map[string]adapter.Endpoint
}

func NewManager(registry adapter.EndpointRegistry) *Manager {
	return &Manager{
		registry:      registry,
		endpointByTag: make(map[string]adapter.Endpoint),
	}
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.access.Lock()
	defer m.access.Unlock()
	if stage == adapter.StartStateInitialize {
		m.scope = scope
	}
	if stage == adapter.StartStateStart {
		return nil
	}
	for _, endpoint := range m.endpoints {
		name := "endpoint/" + endpoint.Type() + "[" + endpoint.Tag() + "]"
		err := scope.Start(name, endpoint, stage)
		if err != nil {
			return err
		}
	}
	if stage == adapter.StartStateStarted {
		m.started = true
	}
	return nil
}

func (m *Manager) StartEndpoint(endpoint adapter.Endpoint) error {
	return m.scope.Start("endpoint/"+endpoint.Type()+"["+endpoint.Tag()+"]", endpoint, adapter.StartStateStart)
}

func (m *Manager) Endpoints() []adapter.Endpoint {
	m.access.Lock()
	defer m.access.Unlock()
	return m.endpoints
}

func (m *Manager) Get(tag string) (adapter.Endpoint, bool) {
	m.access.Lock()
	defer m.access.Unlock()
	endpoint, found := m.endpointByTag[tag]
	return endpoint, found
}

// Remove removes and closes an endpoint; used by hot reload. //H
func (m *Manager) Remove(tag string) error {
	m.access.Lock()
	endpoint, found := m.endpointByTag[tag]
	if !found {
		m.access.Unlock()
		return os.ErrInvalid
	}
	delete(m.endpointByTag, tag)
	index := slices.Index(m.endpoints, endpoint)
	if index == -1 {
		panic("invalid endpoint index")
	}
	m.endpoints = slices.Delete(slices.Clone(m.endpoints), index, index+1) // H: never change a slice already handed out
	started := m.started
	m.access.Unlock()
	if started {
		return adapter.CloseLate(m.scope, endpoint)
	}
	return nil
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) error {
	endpoint, err := m.registry.Create(ctx, router, logger, tag, outboundType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	started := m.started
	m.access.Unlock()
	if started { // H: hot reload; started outside the lock, as starting may look up other endpoints
		err = adapter.StartLate(m.scope, "endpoint/"+endpoint.Type()+"["+endpoint.Tag()+"]", endpoint)
		if err != nil {
			return err
		}
	}
	m.access.Lock()
	existsEndpoint, replaced := m.endpointByTag[tag]
	if replaced && !started {
		m.access.Unlock()
		return E.New("duplicate endpoint tag: ", tag)
	}
	if replaced {
		existsIndex := slices.Index(m.endpoints, existsEndpoint)
		if existsIndex == -1 {
			panic("invalid endpoint index")
		}
		// H: the replacement takes the old one's place (callers rely on the order, e.g. the main group
		// comes first); a copy, so a slice already handed out never changes
		m.endpoints = slices.Clone(m.endpoints)
		m.endpoints[existsIndex] = endpoint
	} else {
		m.endpoints = append(m.endpoints, endpoint)
	}
	m.endpointByTag[tag] = endpoint
	m.access.Unlock()
	if replaced {
		err = adapter.CloseLate(m.scope, existsEndpoint)
		if err != nil {
			return E.Cause(err, "close endpoint/", existsEndpoint.Type(), "[", existsEndpoint.Tag(), "]")
		}
	}
	return nil
}

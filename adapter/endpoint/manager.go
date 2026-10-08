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

func (m *Manager) Remove(tag string) error {
	m.access.Lock()
	endpoint, found := m.endpointByTag[tag]
	if !found {
		m.access.Unlock()
		return os.ErrInvalid
	}
	delete(m.endpointByTag, tag)
	index := common.Index(m.endpoints, func(it adapter.Endpoint) bool {
		return it == endpoint
	})
	if index == -1 {
		panic("invalid endpoint index")
	}
	m.endpoints = slices.Delete(slices.Clone(m.endpoints), index, index+1) // H: never change a slice already handed out
	started := m.started
	m.access.Unlock()
	if started {
		return endpoint.Close()
	}
	return nil
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) error {
	endpoint, err := m.registry.Create(ctx, router, logger, tag, outboundType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	if m.started {
		name := "endpoint/" + endpoint.Type() + "[" + endpoint.Tag() + "]"
		for _, stage := range adapter.ListStartStages {
			done := adapter.LogElapsed(m.logger, stage, " ", name)
			err = adapter.LegacyStart(endpoint, stage)
			done()
			if err != nil {
				return E.Cause(err, stage, " ", name)
			}
		}
	}
	if existsEndpoint, loaded := m.endpointByTag[tag]; loaded {
		if m.started {
			err = existsEndpoint.Close()
			if err != nil {
				return E.Cause(err, "close endpoint/", existsEndpoint.Type(), "[", existsEndpoint.Tag(), "]")
			}
		}
		existsIndex := common.Index(m.endpoints, func(it adapter.Endpoint) bool {
			return it == existsEndpoint
		})
		if existsIndex == -1 {
			panic("invalid endpoint index")
		}
		m.endpoints = slices.Delete(slices.Clone(m.endpoints), existsIndex, existsIndex+1) // H: never change a slice already handed out
	}
	m.endpoints = append(m.endpoints, endpoint)
	m.endpointByTag[tag] = endpoint
	return nil
}

package provider

import (
	"context"
	"os"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.ProviderManager = (*Manager)(nil)

type Manager struct {
	registry      adapter.ProviderRegistry
	access        sync.Mutex
	startAccess   sync.Mutex
	scope         *adapter.Scope
	stage         adapter.StartStage
	providers     []adapter.Provider
	providerByTag map[string]adapter.Provider
}

func NewManager(registry adapter.ProviderRegistry) *Manager {
	return &Manager{
		registry:      registry,
		providerByTag: make(map[string]adapter.Provider),
	}
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.startAccess.Lock()
	defer m.startAccess.Unlock()
	m.access.Lock()
	m.scope = scope
	m.stage = stage
	providers := m.providers
	m.access.Unlock()
	for _, provider := range providers {
		err := scope.Start("provider/"+provider.Type()+"["+provider.Tag()+"]", provider, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) Providers() []adapter.Provider {
	m.access.Lock()
	defer m.access.Unlock()
	return m.providers
}

func (m *Manager) Get(tag string) (adapter.Provider, bool) {
	m.access.Lock()
	provider, found := m.providerByTag[tag]
	m.access.Unlock()
	return provider, found
}

func (m *Manager) Remove(tag string) error {
	m.startAccess.Lock()
	defer m.startAccess.Unlock()
	m.access.Lock()
	provider, found := m.providerByTag[tag]
	if !found {
		m.access.Unlock()
		return os.ErrInvalid
	}
	delete(m.providerByTag, tag)
	m.providers = common.Filter(m.providers, func(it adapter.Provider) bool {
		return it != provider
	})
	scope := m.scope
	m.access.Unlock()
	if scope == nil {
		return nil
	}
	return scope.Remove(provider)
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logFactory log.Factory, tag string, providerType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}
	provider, err := m.registry.CreateProvider(ctx, router, logFactory, tag, providerType, options)
	if err != nil {
		return err
	}
	m.startAccess.Lock()
	defer m.startAccess.Unlock()
	m.access.Lock()
	scope := m.scope
	stage := m.stage
	m.access.Unlock()
	if scope != nil {
		name := "provider/" + provider.Type() + "[" + provider.Tag() + "]"
		for _, startStage := range adapter.ListStartStages[:stage+1] {
			err = scope.Start(name, provider, startStage)
			if err != nil {
				return E.Errors(err, scope.Remove(provider))
			}
		}
	}
	m.access.Lock()
	existsProvider, loaded := m.providerByTag[tag]
	if loaded {
		m.providers = common.Filter(m.providers, func(it adapter.Provider) bool {
			return it != existsProvider
		})
	}
	m.providers = append(m.providers, provider)
	m.providerByTag[tag] = provider
	m.access.Unlock()
	if !loaded || scope == nil {
		return nil
	}
	err = scope.Remove(existsProvider)
	if err != nil {
		return E.Cause(err, "close provider/", existsProvider.Type(), "[", existsProvider.Tag(), "]")
	}
	return nil
}

package dns

import (
	"context"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.DNSTransportManager = (*TransportManager)(nil)

type TransportManager struct {
	registry                 adapter.DNSTransportRegistry
	outbound                 adapter.OutboundManager
	defaultTag               string
	access                   sync.RWMutex
	transports               []adapter.DNSTransport
	transportByTag           map[string]adapter.DNSTransport
	defaultTransport         adapter.DNSTransport
	defaultTransportFallback func() (adapter.DNSTransport, error)
	fakeIPTransport          adapter.FakeIPTransport
}

func NewTransportManager(registry adapter.DNSTransportRegistry, outbound adapter.OutboundManager, defaultTag string) *TransportManager {
	return &TransportManager{
		registry:       registry,
		outbound:       outbound,
		defaultTag:     defaultTag,
		transportByTag: make(map[string]adapter.DNSTransport),
	}
}

func (m *TransportManager) Initialize(defaultTransportFallback func() (adapter.DNSTransport, error)) {
	m.defaultTransportFallback = defaultTransportFallback
}

func (m *TransportManager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.access.Lock()
	if stage == adapter.StartStateInitialize {
		if m.defaultTag != "" && m.defaultTransport == nil {
			m.access.Unlock()
			return E.New("default DNS server not found: ", m.defaultTag)
		}
		if m.defaultTransport == nil {
			defaultTransport, err := m.defaultTransportFallback()
			if err != nil {
				m.access.Unlock()
				return E.Cause(err, "default DNS server fallback")
			}
			m.transports = append(m.transports, defaultTransport)
			m.transportByTag[defaultTransport.Tag()] = defaultTransport
			m.defaultTransport = defaultTransport
		}
	}
	transports := m.transports
	m.access.Unlock()
	if stage == adapter.StartStateStart {
		return m.startTransports(scope, transports)
	}
	for _, transport := range transports {
		name := "dns/" + transport.Type() + "[" + transport.Tag() + "]"
		err := scope.Start(name, transport, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *TransportManager) startTransports(scope *adapter.Scope, transports []adapter.DNSTransport) error {
	started := make(map[string]bool)
	for {
		canContinue := false
	startOne:
		for _, transportToStart := range transports {
			transportTag := transportToStart.Tag()
			if started[transportTag] {
				continue
			}
			dependencies := transportToStart.Dependencies()
			for _, dependency := range dependencies {
				if !started[dependency] {
					continue startOne
				}
			}
			started[transportTag] = true
			canContinue = true
			name := "dns/" + transportToStart.Type() + "[" + transportTag + "]"
			err := scope.Start(name, transportToStart, adapter.StartStateStart)
			if err != nil {
				return err
			}
		}
		if len(started) == len(transports) {
			break
		}
		if canContinue {
			continue
		}
		currentTransport := common.Find(transports, func(it adapter.DNSTransport) bool {
			return !started[it.Tag()]
		})
		var lintTransport func(oTree []string, oCurrent adapter.DNSTransport) error
		lintTransport = func(oTree []string, oCurrent adapter.DNSTransport) error {
			problemTransportTag := common.Find(oCurrent.Dependencies(), func(it string) bool {
				return !started[it]
			})
			if common.Contains(oTree, problemTransportTag) {
				return E.New("circular server dependency: ", strings.Join(oTree, " -> "), " -> ", problemTransportTag)
			}
			m.access.Lock()
			problemTransport := m.transportByTag[problemTransportTag]
			m.access.Unlock()
			if problemTransport == nil {
				return E.New("dependency[", problemTransportTag, "] not found for server[", oCurrent.Tag(), "]")
			}
			return lintTransport(append(oTree, problemTransportTag), problemTransport)
		}
		return lintTransport([]string{currentTransport.Tag()}, currentTransport)
	}
	return nil
}

func (m *TransportManager) Transports() []adapter.DNSTransport {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.transports
}

func (m *TransportManager) Transport(tag string) (adapter.DNSTransport, bool) {
	m.access.RLock()
	outbound, found := m.transportByTag[tag]
	m.access.RUnlock()
	return outbound, found
}

func (m *TransportManager) Default() adapter.DNSTransport {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.defaultTransport
}

func (m *TransportManager) FakeIP() adapter.FakeIPTransport {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.fakeIPTransport
}

func (m *TransportManager) Remove(tag string) error {
	return m.remove(tag, false)
}

// RemoveForReload removes a server even while others still depend on it; used by hot reload,
// which recreates those dependents in the same reload. //H
func (m *TransportManager) RemoveForReload(tag string) error {
	return m.remove(tag, true)
}

func (m *TransportManager) remove(tag string, ignoreDependents bool) error {
	m.access.Lock()
	defer m.access.Unlock()
	transport, found := m.transportByTag[tag]
	if !found {
		return os.ErrInvalid
	}
	delete(m.transportByTag, tag)
	index := common.Index(m.transports, func(it adapter.DNSTransport) bool {
		return it == transport
	})
	if index == -1 {
		panic("invalid inbound index")
	}
	m.transports = slices.Delete(slices.Clone(m.transports), index, index+1) // H: never change a slice already handed out
	started := m.started
	if m.defaultTransport == transport {
		if len(m.transports) > 0 {
			nextTransport := m.transports[0]
			if nextTransport.Type() == C.DNSTypeFakeIP { // H: was inverted
				return E.New("default server cannot be fakeip")
			}
			m.defaultTransport = nextTransport
			m.logger.Info("updated default server to ", m.defaultTransport.Tag())
		} else {
			m.defaultTransport = nil
		}
	}
	dependBy := m.dependByTag[tag]
	if len(dependBy) > 0 && !ignoreDependents {
		return E.New("server[", tag, "] is depended by ", strings.Join(dependBy, ", "))
	}
	m.removeDependencies(tag, transport.Dependencies())
	if m.fakeIPTransport != nil && adapter.DNSTransport(m.fakeIPTransport) == transport {
		m.fakeIPTransport = nil
	}
	if started {
		transport.Close()
	}
	return nil
}

func (m *TransportManager) Create(ctx context.Context, logger log.ContextLogger, tag string, transportType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}
	transport, err := m.registry.CreateDNSTransport(ctx, logger, tag, transportType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	if m.started {
		for _, stage := range adapter.ListStartStages {
			err = adapter.LegacyStart(transport, stage)
			if err != nil {
				return E.Cause(err, stage, " dns/", transport.Type(), "[", transport.Tag(), "]")
			}
		}
	}
	if existsTransport, loaded := m.transportByTag[tag]; loaded {
		if m.started {
			err = common.Close(existsTransport)
			if err != nil {
				return E.Cause(err, "close dns/", existsTransport.Type(), "[", existsTransport.Tag(), "]")
			}
		}
		existsIndex := common.Index(m.transports, func(it adapter.DNSTransport) bool {
			return it == existsTransport
		})
		if existsIndex == -1 {
			panic("invalid inbound index")
		}
		m.transports = slices.Delete(slices.Clone(m.transports), existsIndex, existsIndex+1) // H: never change a slice already handed out
		// H: the replaced server no longer depends on anything, nor is it the fakeip server
		m.removeDependencies(tag, existsTransport.Dependencies())
		if m.fakeIPTransport != nil && adapter.DNSTransport(m.fakeIPTransport) == existsTransport {
			m.fakeIPTransport = nil
		}
	}
	m.transports = append(m.transports, transport)
	m.transportByTag[tag] = transport
	if tag == m.defaultTag || (m.defaultTag == "" && m.defaultTransport == nil) {
		if transport.Type() == C.DNSTypeFakeIP {
			return E.New("default server cannot be fakeip")
		}
		m.defaultTransport = transport
	}
	if transport.Type() == C.DNSTypeFakeIP {
		if m.fakeIPTransport != nil {
			return E.New("multiple fakeip server are not supported")
		}
		m.fakeIPTransport = transport.(adapter.FakeIPTransport)
	}
	return nil
}

func (m *TransportManager) removeDependencies(tag string, dependencies []string) {
	for _, dependency := range dependencies {
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

// SetDefaultTag changes the default server (dns.final); used by hot reload. //H
func (m *TransportManager) SetDefaultTag(tag string) error {
	m.access.Lock()
	defer m.access.Unlock()
	m.defaultTag = tag
	if tag == "" {
		return nil
	}
	transport, loaded := m.transportByTag[tag]
	if !loaded {
		return E.New("default DNS server not found: ", tag)
	}
	if transport.Type() == C.DNSTypeFakeIP {
		return E.New("default server cannot be fakeip")
	}
	if m.defaultTransport != transport {
		m.defaultTransport = transport
		m.logger.Info("updated default server to ", transport.Tag())
	}
	return nil
}

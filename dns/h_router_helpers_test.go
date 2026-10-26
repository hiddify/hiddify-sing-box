// Test doubles for the DNS router, carried over from upstream's dns/router_test.go, which
// sing-box 1.15 removed; hiddify's router tests still use them. //H
package dns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type routerTestFakeDNSTransport struct {
	tag           string
	transportType string
}

func (t *routerTestFakeDNSTransport) Start(adapter.StartStage, *adapter.Scope) error { return nil }

func (t *routerTestFakeDNSTransport) Close() error { return nil }

func (t *routerTestFakeDNSTransport) Type() string { return t.transportType }

func (t *routerTestFakeDNSTransport) Tag() string { return t.tag }

func (t *routerTestFakeDNSTransport) Dependencies() []string { return nil }

func (t *routerTestFakeDNSTransport) Reset() {}

func (t *routerTestFakeDNSTransport) Exchange(context.Context, *mDNS.Msg) (*mDNS.Msg, error) {
	return nil, E.New("unused transport exchange")
}

func (t *routerTestFakeDNSTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	response, err := t.Exchange(ctx, message)
	callback(response, err)
}

type routerTestFakeDNSTransportManager struct {
	defaultTransport adapter.DNSTransport
	transports       map[string]adapter.DNSTransport
}

func (m *routerTestFakeDNSTransportManager) Start(adapter.StartStage, *adapter.Scope) error {
	return nil
}

func (m *routerTestFakeDNSTransportManager) Close() error { return nil }

func (m *routerTestFakeDNSTransportManager) Transports() []adapter.DNSTransport {
	transports := make([]adapter.DNSTransport, 0, len(m.transports))
	for _, transport := range m.transports {
		transports = append(transports, transport)
	}
	return transports
}

func (m *routerTestFakeDNSTransportManager) Transport(tag string) (adapter.DNSTransport, bool) {
	transport, loaded := m.transports[tag]
	return transport, loaded
}

func (m *routerTestFakeDNSTransportManager) Default() adapter.DNSTransport { return m.defaultTransport }

func (m *routerTestFakeDNSTransportManager) FakeIP() adapter.FakeIPTransport {
	return nil
}

func (m *routerTestFakeDNSTransportManager) Remove(string) error { return nil }

func (m *routerTestFakeDNSTransportManager) Create(context.Context, log.ContextLogger, string, string, any) error {
	return E.New("unsupported")
}

type fakeDNSClient struct {
	beforeExchange func(ctx context.Context, transport adapter.DNSTransport, message *mDNS.Msg)
	exchange       func(transport adapter.DNSTransport, message *mDNS.Msg) (*mDNS.Msg, error)
	lookupWithCtx  func(ctx context.Context, transport adapter.DNSTransport, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, *mDNS.Msg, error)
	lookup         func(transport adapter.DNSTransport, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, *mDNS.Msg, error)
}

func (c *fakeDNSClient) Start() {}

func (c *fakeDNSClient) Exchange(ctx context.Context, transport adapter.DNSTransport, message *mDNS.Msg, _ adapter.DNSQueryOptions, _ func(*mDNS.Msg) bool) (*mDNS.Msg, error) {
	if c.beforeExchange != nil {
		c.beforeExchange(ctx, transport, message)
	}
	if c.exchange == nil {
		if len(message.Question) != 1 {
			return nil, E.New("unused client exchange")
		}
		var (
			addresses []netip.Addr
			response  *mDNS.Msg
			err       error
		)
		if c.lookupWithCtx != nil {
			addresses, response, err = c.lookupWithCtx(ctx, transport, FqdnToDomain(message.Question[0].Name), adapter.DNSQueryOptions{})
		} else if c.lookup != nil {
			addresses, response, err = c.lookup(transport, FqdnToDomain(message.Question[0].Name), adapter.DNSQueryOptions{})
		} else {
			return nil, E.New("unused client exchange")
		}
		if err != nil {
			return nil, err
		}
		if response != nil {
			return response, nil
		}
		return FixedResponse(0, message.Question[0], addresses, 60), nil
	}
	return c.exchange(transport, message)
}

func (c *fakeDNSClient) ExchangeAsync(ctx context.Context, transport adapter.DNSTransport, message *mDNS.Msg, options adapter.DNSQueryOptions, responseChecker func(*mDNS.Msg) bool, callback func(response *mDNS.Msg, err error)) {
	response, err := c.Exchange(ctx, transport, message, options, responseChecker)
	callback(response, err)
}

func (c *fakeDNSClient) Lookup(ctx context.Context, transport adapter.DNSTransport, domain string, options adapter.DNSQueryOptions, responseChecker func(*mDNS.Msg) bool) ([]netip.Addr, error) {
	if c.lookup == nil && c.lookupWithCtx == nil {
		return nil, E.New("unused client lookup")
	}
	var (
		addresses []netip.Addr
		response  *mDNS.Msg
		err       error
	)
	if c.lookupWithCtx != nil {
		addresses, response, err = c.lookupWithCtx(ctx, transport, domain, options)
	} else {
		addresses, response, err = c.lookup(transport, domain, options)
	}
	if err != nil {
		return nil, err
	}
	if response == nil {
		response = FixedResponse(0, fixedQuestion(domain, mDNS.TypeA), addresses, 60)
	}
	if responseChecker != nil && !responseChecker(response) {
		return nil, ErrResponseRejected
	}
	if addresses != nil {
		return addresses, nil
	}
	return MessageToAddresses(response), nil
}

func (c *fakeDNSClient) ClearCache() {}

func newTestRouter(t *testing.T, rules []option.DNSRule, transportManager *routerTestFakeDNSTransportManager, client *fakeDNSClient) *Router {
	router := newTestRouterWithContext(t, context.Background(), rules, transportManager, client)
	return router
}

func newTestRouterWithContext(t *testing.T, ctx context.Context, rules []option.DNSRule, transportManager *routerTestFakeDNSTransportManager, client *fakeDNSClient) *Router {
	return newTestRouterWithContextAndLogger(t, ctx, rules, transportManager, client, log.NewNOPFactory().NewLogger("dns"))
}

func newTestRouterWithContextAndLogger(t *testing.T, ctx context.Context, rules []option.DNSRule, transportManager *routerTestFakeDNSTransportManager, client *fakeDNSClient, dnsLogger log.ContextLogger) *Router {
	t.Helper()
	router := &Router{
		ctx:                   ctx,
		logger:                dnsLogger,
		transport:             transportManager,
		client:                client,
		rawRules:              make([]option.DNSRule, 0, len(rules)),
		rules:                 make([]adapter.DNSRule, 0, len(rules)),
		defaultDomainStrategy: C.DomainStrategyAsIS,
	}
	if rules != nil {
		err := router.Initialize(rules)
		require.NoError(t, err)
		scope := adapter.NewScope(ctx, dnsLogger)
		t.Cleanup(func() { scope.Close() })
		err = router.Start(adapter.StartStateStart, scope)
		require.NoError(t, err)
	}
	return router
}

func fixedQuestion(name string, qType uint16) mDNS.Question {
	return mDNS.Question{
		Name:   mDNS.Fqdn(name),
		Qtype:  qType,
		Qclass: mDNS.ClassINET,
	}
}

func mustRecord(t *testing.T, record string) option.DNSRecordOptions {
	t.Helper()
	var value option.DNSRecordOptions
	require.NoError(t, value.UnmarshalJSON([]byte(`"`+record+`"`)))
	return value
}

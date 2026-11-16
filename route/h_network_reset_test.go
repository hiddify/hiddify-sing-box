package route

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// hResetDNSServer is a DNS server that counts its resets and answers with address, or fails
// while it has none.
type hResetDNSServer struct {
	adapter.DNSTransport
	tag     string
	address atomic.Pointer[string]
	calls   atomic.Int32
	resets  atomic.Int32
}

func (s *hResetDNSServer) Tag() string  { return s.tag }
func (s *hResetDNSServer) Type() string { return C.DNSTypeUDP }
func (s *hResetDNSServer) Reset()       { s.resets.Add(1) }

func (s *hResetDNSServer) ExchangeAsync(_ context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	s.calls.Add(1)
	address := s.address.Load()
	go func() {
		if address == nil {
			callback(nil, errors.New("server failed"))
			return
		}
		response := new(mDNS.Msg).SetReply(message)
		response.Answer = append(response.Answer, &mDNS.A{
			Hdr: mDNS.RR_Header{Name: message.Question[0].Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 60},
			A:   []byte{10, 0, 0, (*address)[0]},
		})
		callback(response, nil)
	}()
}

type hResetDNSServers struct {
	adapter.DNSTransportManager
	servers []adapter.DNSTransport
}

func (m *hResetDNSServers) Transports() []adapter.DNSTransport { return m.servers }

func (m *hResetDNSServers) Transport(tag string) (adapter.DNSTransport, bool) {
	for _, server := range m.servers {
		if server.Tag() == tag {
			return server, true
		}
	}
	return nil, false
}

type hResetHTTPClients struct {
	adapter.HTTPClientManager
	resets atomic.Int32
}

func (m *hResetHTTPClients) ResetNetwork() { m.resets.Add(1) }

type hResetNoEndpoints struct{ adapter.EndpointManager }

func (hResetNoEndpoints) Endpoints() []adapter.Endpoint { return nil }

type hResetNoInbounds struct{ adapter.InboundManager }

func (hResetNoInbounds) Inbounds() []adapter.Inbound { return nil }

type hResetNoOutbounds struct{ adapter.OutboundManager }

func (hResetNoOutbounds) Outbounds() []adapter.Outbound { return nil }

// A network reset goes on to the router: the HTTP clients and every DNS server are reset, and a
// sequential DNS group forgets the scores it gave its servers on the network that is gone.
func TestH_NetworkResetReachesTheDNSServers(t *testing.T) {
	first := &hResetDNSServer{tag: "first"}
	second := &hResetDNSServer{tag: "second"}
	second.address.Store(new("\x02"))
	servers := &hResetDNSServers{servers: []adapter.DNSTransport{first, second}}
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), servers)
	group, err := transport.NewGroup(ctx, log.NewNOPFactory().Logger(), "group", option.GroupDNSServerOptions{
		Mode:    C.DNSGroupModeSequential,
		Servers: []string{"first", "second"},
	})
	require.NoError(t, err)
	servers.servers = append(servers.servers, group)

	dnsRouter, err := dns.NewRouter(ctx, log.NewNOPFactory(), option.DNSOptions{})
	require.NoError(t, err)
	httpClients := &hResetHTTPClients{}
	manager := &NetworkManager{
		ctx:      context.Background(),
		router:   &Router{dns: dnsRouter, httpClientManager: httpClients},
		endpoint: hResetNoEndpoints{},
		inbound:  hResetNoInbounds{},
		outbound: hResetNoOutbounds{},
	}

	ask := func() byte {
		t.Helper()
		queryCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		response, err := group.Exchange(queryCtx, new(mDNS.Msg).SetQuestion("example.com.", mDNS.TypeA))
		require.NoError(t, err)
		require.Len(t, response.Answer, 1)
		return response.Answer[0].(*mDNS.A).A[3]
	}

	// on the old network the first server fails, so the group asks the second one first
	require.EqualValues(t, 2, ask())
	require.EqualValues(t, 2, ask())
	require.EqualValues(t, 1, first.calls.Load(), "the failed server is behind the one that answers")

	// the new network: the first server answers
	first.address.Store(new("\x01"))
	manager.ResetNetwork(context.Background())

	require.EqualValues(t, 1, httpClients.resets.Load(), "the HTTP clients are reset")
	require.EqualValues(t, 1, first.resets.Load(), "every DNS server is reset")
	require.EqualValues(t, 1, second.resets.Load(), "every DNS server is reset")
	require.EqualValues(t, 1, ask(), "the group forgot its scores: the first server is first again")
}

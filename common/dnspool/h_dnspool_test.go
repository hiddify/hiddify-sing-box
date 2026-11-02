package dnspool

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	multidns "github.com/hiddify/hmrd_multi_resolver_dns"
	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/stretchr/testify/require"
)

func TestH_DnspoolExpand(t *testing.T) {
	t.Parallel()
	builtin := BuiltinResolvers()
	require.NotEmpty(t, builtin)
	require.NotEmpty(t, BuiltinResolversByCountry())
	for ip, country := range builtin {
		require.Equal(t, country, Country(ip))
		break
	}
	require.Equal(t, "", Country("203.0.113.1"))

	candidates := Expand([]string{" 8.8.8.8:53 ", "dot://1.1.1.1:853", "https://dns.google/dns-query"})
	require.Equal(t, []Candidate{{Address: "8.8.8.8:53"}, {Address: "dot://1.1.1.1:853"}, {Address: "https://dns.google/dns-query"}}, candidates)
	require.False(t, HasAuto([]string{"8.8.8.8"}))

	for _, auto := range []string{"auto", "AUTO", ""} {
		require.True(t, HasAuto([]string{"1.1.1.1", auto}))
		candidates = Expand([]string{auto, "4.4.4.4:53"})
		require.Len(t, candidates, len(builtin)+1)
		for _, c := range candidates[:len(candidates)-1] {
			require.True(t, c.Auto)
			ip := strings.TrimSuffix(c.Address, ":53")
			_, known := builtin[ip]
			require.True(t, known, c.Address)
		}
		require.Equal(t, Candidate{Address: "4.4.4.4:53"}, candidates[len(candidates)-1])
	}
	require.Empty(t, Expand(nil))
}

type memoryCache struct {
	adapter.CacheFile
	mu   sync.Mutex
	data map[string]*adapter.SavedBinary
}

func (c *memoryCache) LoadBinary(tag string) *adapter.SavedBinary {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data[tag]
}

func (c *memoryCache) SaveBinary(tag string, set *adapter.SavedBinary) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[tag] = set
	return nil
}

func TestH_DnspoolHistory(t *testing.T) {
	t.Parallel()
	h := NewHistory()
	require.Equal(t, 0, h.Score("a"))
	require.Equal(t, -4, h.Record("a", -4))
	require.Equal(t, -10, h.Record("a", -20))
	// a success forgets the failures first
	require.Equal(t, 1, h.Record("a", 1))
	require.Equal(t, 10, h.Record("a", 30))
	require.Equal(t, 7, h.Record("a", -3))

	// save and load through the cache; a nil cache and bad content are harmless
	logger := log.NewNOPFactory().Logger()
	h.Save(nil, "k", logger)
	require.Empty(t, LoadHistory(nil, "k").ResolverRate)
	cache := &memoryCache{data: map[string]*adapter.SavedBinary{}}
	h.Save(cache, "k", logger)
	require.Equal(t, map[string]int{"a": 7}, LoadHistory(cache, "k").ResolverRate)
	require.Empty(t, LoadHistory(cache, "other").ResolverRate)
	cache.data["bad"] = &adapter.SavedBinary{Content: []byte("{not json")}
	require.NotNil(t, LoadHistory(cache, "bad").ResolverRate)

	// order: built-in first, then by score, so the best known come first
	h = NewHistory()
	h.Record("good", 5)
	h.Record("bad", -5)
	candidates := []Candidate{{Address: "bad"}, {Address: "new"}, {Address: "good"}, {Address: "auto1", Auto: true}, {Address: "auto2", Auto: true}}
	h.Sort(candidates)
	require.True(t, candidates[0].Auto)
	require.True(t, candidates[1].Auto)
	require.Equal(t, "good", candidates[2].Address)
	require.Equal(t, "new", candidates[3].Address)
	require.Equal(t, "bad", candidates[4].Address)
}

func TestH_DnspoolQueryType(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]uint16{
		"a": dns.TypeA, "aaaa": dns.TypeAAAA, "cname": dns.TypeCNAME, "mx": dns.TypeMX,
		"ns": dns.TypeNS, "ptr": dns.TypePTR, "soa": dns.TypeSOA, "srv": dns.TypeSRV,
		"txt": dns.TypeTXT, "bogus": dns.TypeA, "": dns.TypeA,
	} {
		require.Equal(t, want, QueryType(in), in)
	}
	msg := BuildQuery("example.com", dns.TypeTXT)
	require.True(t, msg.RecursionDesired)
	require.Len(t, msg.Question, 1)
	require.Equal(t, "example.com.", msg.Question[0].Name)
	require.Equal(t, dns.TypeTXT, msg.Question[0].Qtype)
}

func TestH_DnspoolProtocolAndLB(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"": "udp", "udp": "udp", "tcp": "tcp", "tls": "dot", "dot": "dot", "https": "doh", "doh": "doh", " DoH ": "doh"} {
		proto, err := ProtocolFromString(in)
		require.NoError(t, err, in)
		require.Equal(t, want, string(proto), in)
	}
	_, err := ProtocolFromString("quic")
	require.Error(t, err)
	require.Equal(t, LBFromString("weighted"), LBFromString("WEIGHTED"))
	require.NotEqual(t, LBFromString("weighted"), LBFromString(""))
	require.Equal(t, LBFromString("lowest_latency"), LBFromString("lowest-latency"))
	require.Equal(t, LBFromString(""), LBFromString("unknown"))
	require.Equal(t, multidns.LBAuto, LBFromString(""))
	require.Equal(t, multidns.LBAuto, LBFromString("auto"))
	require.Equal(t, multidns.LBRoundRobin, LBFromString("roundrobin"))
}

// startLocalDNS runs a UDP and TCP DNS server that answers found.test with an A record.
func startLocalDNS(t *testing.T) string {
	t.Helper()
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Name == "found.test." {
			rr, _ := dns.NewRR("found.test. 60 IN A 192.0.2.1")
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	require.NoError(t, err)
	udp := &dns.Server{PacketConn: pc, Handler: handler}
	tcp := &dns.Server{Listener: ln, Handler: handler}
	go udp.ActivateAndServe()
	go tcp.ActivateAndServe()
	t.Cleanup(func() { udp.Shutdown(); tcp.Shutdown() })
	return pc.LocalAddr().String()
}

func TestH_DnspoolProbe(t *testing.T) {
	t.Parallel()
	addr := startLocalDNS(t)
	logger := log.NewNOPFactory().Logger()
	ctx := context.Background()

	for _, resolver := range []string{addr, "udp://" + addr, "tcp://" + addr} {
		resp, err := Probe(ctx, logger, resolver, "found.test", dns.TypeA, option.DialerOptions{})
		require.NoError(t, err, resolver)
		require.NoError(t, CheckAnswer(resolver, resp, err))
		require.Equal(t, "192.0.2.1", resp.Answer[0].(*dns.A).A.String())
	}
	resp, err := Probe(ctx, logger, addr, "empty.test", dns.TypeA, option.DialerOptions{})
	require.NoError(t, err)
	require.ErrorContains(t, CheckAnswer(addr, resp, err), "no record")

	_, err = Probe(ctx, logger, "no-port", "found.test", dns.TypeA, option.DialerOptions{})
	require.Error(t, err)
	_, err = Probe(ctx, logger, "quic://1.1.1.1", "found.test", dns.TypeA, option.DialerOptions{})
	require.Error(t, err)
	_, err = Probe(ctx, logger, "https://[bad/dns-query", "found.test", dns.TypeA, option.DialerOptions{})
	require.Error(t, err)
}

// A pool listens locally, and a query to it is answered by a resolver added to it.
func TestH_DnspoolPool(t *testing.T) {
	t.Parallel()
	upstream := startLocalDNS(t)
	logger := log.NewNOPFactory().Logger()
	dial, err := DialFunc(context.Background(), option.DialerOptions{})
	require.NoError(t, err)
	pool, err := StartPool(logger, "test", PoolOptions{LoadBalance: "lowest_latency"}, dial)
	require.NoError(t, err)
	host, _, err := net.SplitHostPort(pool.Addr())
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", host)
	require.NotNil(t, pool.Manager())

	require.Error(t, pool.Add("quic://1.1.1.1"))
	require.NoError(t, pool.Add(upstream))

	resp, err := Probe(context.Background(), logger, pool.Addr(), "found.test", dns.TypeA, option.DialerOptions{})
	require.NoError(t, err)
	require.NoError(t, CheckAnswer(pool.Addr(), resp, err))
	require.NoError(t, pool.Close())
	require.NoError(t, pool.Close())

	var nilPool *Pool
	require.NoError(t, nilPool.Close())

	require.Equal(t, PoolOptions{}, PoolOptionsFrom(nil))
	from := PoolOptionsFrom(&option.SmartPoolOptions{Enabled: true, LoadBalance: "weighted", Deadline: badoption.Duration(time.Second), DownAfter: 3, Duplicate: 2})
	require.Equal(t, PoolOptions{LoadBalance: "weighted", Deadline: time.Second, DownAfter: 3, Duplicate: 2}, from)
}

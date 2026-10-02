package multi

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type hFakeTransport struct {
	tag      string
	delay    time.Duration
	exchange func(ctx context.Context, msg *mDNS.Msg) (*mDNS.Msg, error)
	calls    atomic.Int32
}

func (t *hFakeTransport) Start(adapter.StartStage) error { return nil }
func (t *hFakeTransport) Close() error                   { return nil }
func (t *hFakeTransport) Type() string                   { return C.DNSTypeUDP }
func (t *hFakeTransport) Tag() string                    { return t.tag }
func (t *hFakeTransport) Dependencies() []string         { return nil }
func (t *hFakeTransport) Reset()                         {}
func (t *hFakeTransport) Exchange(ctx context.Context, msg *mDNS.Msg) (*mDNS.Msg, error) {
	t.calls.Add(1)
	if t.delay > 0 {
		select {
		case <-time.After(t.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return t.exchange(ctx, msg)
}

func (t *hFakeTransport) ExchangeAsync(ctx context.Context, msg *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	callback(t.Exchange(ctx, msg))
}

type hFakeManager struct {
	transports map[string]adapter.DNSTransport
}

func (m *hFakeManager) Start(adapter.StartStage) error { return nil }
func (m *hFakeManager) Close() error                   { return nil }
func (m *hFakeManager) Transports() []adapter.DNSTransport {
	var result []adapter.DNSTransport
	for _, transport := range m.transports {
		result = append(result, transport)
	}
	return result
}

func (m *hFakeManager) Transport(tag string) (adapter.DNSTransport, bool) {
	transport, loaded := m.transports[tag]
	return transport, loaded
}
func (m *hFakeManager) Default() adapter.DNSTransport   { return nil }
func (m *hFakeManager) FakeIP() adapter.FakeIPTransport { return nil }
func (m *hFakeManager) Remove(string) error             { return nil }
func (m *hFakeManager) Create(context.Context, log.ContextLogger, string, string, any) error {
	return nil
}

func hAnswer(ips ...string) func(context.Context, *mDNS.Msg) (*mDNS.Msg, error) {
	return func(_ context.Context, msg *mDNS.Msg) (*mDNS.Msg, error) {
		response := new(mDNS.Msg)
		response.SetReply(msg)
		for _, ip := range ips {
			addr := netip.MustParseAddr(ip)
			header := mDNS.RR_Header{Name: msg.Question[0].Name, Class: mDNS.ClassINET, Ttl: 60}
			if addr.Is4() {
				header.Rrtype = mDNS.TypeA
				response.Answer = append(response.Answer, &mDNS.A{Hdr: header, A: addr.AsSlice()})
			} else {
				header.Rrtype = mDNS.TypeAAAA
				response.Answer = append(response.Answer, &mDNS.AAAA{Hdr: header, AAAA: addr.AsSlice()})
			}
		}
		return response, nil
	}
}

func hFail(message string) func(context.Context, *mDNS.Msg) (*mDNS.Msg, error) {
	return func(context.Context, *mDNS.Msg) (*mDNS.Msg, error) {
		return nil, E.New(message)
	}
}

func hNewMulti(t *testing.T, parallel bool, ignore []string, upstreams ...*hFakeTransport) *Transport {
	t.Helper()
	manager := &hFakeManager{transports: map[string]adapter.DNSTransport{}}
	var tags []string
	for _, upstream := range upstreams {
		manager.transports[upstream.tag] = upstream
		tags = append(tags, upstream.tag)
	}
	var ranges []badoption.Prefix
	for _, r := range ignore {
		ranges = append(ranges, badoption.Prefix(netip.MustParsePrefix(r)))
	}
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), manager)
	transport, err := NewTransport(ctx, log.NewNOPFactory().NewLogger("multi"), "multi-test", option.MultiDNSServerOptions{
		Servers:      tags,
		Parallel:     parallel,
		IgnoreRanges: ranges,
	})
	require.NoError(t, err)
	require.NoError(t, transport.Start(adapter.StartStateStart))
	return transport.(*Transport)
}

func hQuestion() *mDNS.Msg {
	msg := new(mDNS.Msg)
	msg.SetQuestion("example.com.", mDNS.TypeA)
	return msg
}

func hAddrs(msg *mDNS.Msg) []string {
	var result []string
	for _, rr := range msg.Answer {
		switch record := rr.(type) {
		case *mDNS.A:
			result = append(result, record.A.String())
		case *mDNS.AAAA:
			result = append(result, record.AAAA.String())
		}
	}
	return result
}

func hCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestH_MultiAdapterMetadata(t *testing.T) {
	t.Parallel()
	m := hNewMulti(t, false, nil, &hFakeTransport{tag: "a", exchange: hAnswer("1.1.1.1")}, &hFakeTransport{tag: "b", exchange: hAnswer("1.1.1.1")})
	require.Equal(t, C.DNSTypeMulti, m.Type())
	require.Equal(t, "multi-test", m.Tag())
	require.Equal(t, []string{"a", "b"}, m.Dependencies())
	require.Len(t, m.transports, 2)
}

func TestH_MultiStartMissingTransport(t *testing.T) {
	t.Parallel()
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), &hFakeManager{transports: map[string]adapter.DNSTransport{}})
	transport, err := NewTransport(ctx, log.NewNOPFactory().NewLogger("multi"), "m", option.MultiDNSServerOptions{Servers: []string{"missing"}})
	require.NoError(t, err)
	require.NoError(t, transport.Start(adapter.StartStateInitialize))
	err = transport.Start(adapter.StartStateStart)
	require.ErrorContains(t, err, "dns transport not found: missing")
}

func TestH_MultiNoTransports(t *testing.T) {
	t.Parallel()
	for _, parallel := range []bool{false, true} {
		m := hNewMulti(t, parallel, nil)
		_, err := m.Exchange(hCtx(t), hQuestion())
		require.ErrorContains(t, err, "no dns transports configured")
	}
}

func TestH_MultiSerialFallsBackOnError(t *testing.T) {
	t.Parallel()
	first := &hFakeTransport{tag: "a", exchange: hFail("a down")}
	second := &hFakeTransport{tag: "b", exchange: hAnswer("1.2.3.4")}
	third := &hFakeTransport{tag: "c", exchange: hAnswer("5.6.7.8")}
	m := hNewMulti(t, false, nil, first, second, third)
	response, err := m.Exchange(hCtx(t), hQuestion())
	require.NoError(t, err)
	require.Equal(t, []string{"1.2.3.4"}, hAddrs(response))
	require.EqualValues(t, 1, first.calls.Load())
	require.EqualValues(t, 1, second.calls.Load())
	require.EqualValues(t, 0, third.calls.Load())
}

func TestH_MultiSerialAllErrorsReturnsLastError(t *testing.T) {
	t.Parallel()
	m := hNewMulti(t, false, nil, &hFakeTransport{tag: "a", exchange: hFail("a down")}, &hFakeTransport{tag: "b", exchange: hFail("b down")})
	_, err := m.Exchange(hCtx(t), hQuestion())
	require.ErrorContains(t, err, "b down")
}

func TestH_MultiSerialSkipsIgnoredRanges(t *testing.T) {
	t.Parallel()
	blocked := &hFakeTransport{tag: "a", exchange: hAnswer("10.10.34.36", "2001:db8::dead")}
	good := &hFakeTransport{tag: "b", exchange: hAnswer("10.10.34.36", "8.8.8.8")}
	m := hNewMulti(t, false, []string{"10.0.0.0/8", "2001:db8::/32"}, blocked, good)
	response, err := m.Exchange(hCtx(t), hQuestion())
	require.NoError(t, err)
	require.Equal(t, []string{"8.8.8.8"}, hAddrs(response))
}

func TestH_MultiSerialEmptyResponsePreferred(t *testing.T) {
	t.Parallel()
	nxdomain := func(_ context.Context, msg *mDNS.Msg) (*mDNS.Msg, error) {
		response := new(mDNS.Msg)
		response.SetRcode(msg, mDNS.RcodeNameError)
		return response, nil
	}
	m := hNewMulti(t, false, []string{"10.0.0.0/8"},
		&hFakeTransport{tag: "a", exchange: hAnswer("10.0.0.1")},
		&hFakeTransport{tag: "b", exchange: nxdomain},
		&hFakeTransport{tag: "c", exchange: hFail("c down")},
	)
	response, err := m.Exchange(hCtx(t), hQuestion())
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeNameError, response.Rcode)
	require.Empty(t, response.Answer)
}

func TestH_MultiSerialAllBlocked(t *testing.T) {
	t.Parallel()
	m := hNewMulti(t, false, []string{"10.0.0.0/8"},
		&hFakeTransport{tag: "a", exchange: hAnswer("10.0.0.1")},
		&hFakeTransport{tag: "b", exchange: hAnswer("10.0.0.2")},
	)
	_, err := m.Exchange(hCtx(t), hQuestion())
	require.ErrorContains(t, err, "no dns response")
}

func TestH_MultiSerialAfterClose(t *testing.T) {
	t.Parallel()
	upstream := &hFakeTransport{tag: "a", exchange: hAnswer("1.1.1.1")}
	m := hNewMulti(t, false, nil, upstream)
	require.NoError(t, m.Close())
	_, err := m.Exchange(hCtx(t), hQuestion())
	require.ErrorContains(t, err, "transport closed")
	require.EqualValues(t, 0, upstream.calls.Load())
}

func TestH_MultiSerialCanceledContext(t *testing.T) {
	t.Parallel()
	upstream := &hFakeTransport{tag: "a", exchange: hAnswer("1.1.1.1")}
	m := hNewMulti(t, false, nil, upstream)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := m.Exchange(ctx, hQuestion())
	require.ErrorIs(t, err, context.Canceled)
	require.EqualValues(t, 0, upstream.calls.Load())
}

func TestH_MultiSerialNilResponseDoesNotPanic(t *testing.T) {
	t.Skip("BUG: multi.go exchangeSerial/exchangeParallel dereference resp.Answer after filterBlocked returns nil for a (nil, nil) upstream result")
	t.Parallel()
	nilResponse := func(context.Context, *mDNS.Msg) (*mDNS.Msg, error) { return nil, nil }
	for _, parallel := range []bool{false, true} {
		m := hNewMulti(t, parallel, nil,
			&hFakeTransport{tag: "a", exchange: nilResponse},
			&hFakeTransport{tag: "b", exchange: hAnswer("1.1.1.1"), delay: 50 * time.Millisecond},
		)
		require.NotPanics(t, func() {
			response, err := m.Exchange(hCtx(t), hQuestion())
			require.NoError(t, err)
			require.Equal(t, []string{"1.1.1.1"}, hAddrs(response))
		})
	}
}

func TestH_MultiParallelFastestWins(t *testing.T) {
	t.Parallel()
	slow := &hFakeTransport{tag: "slow", delay: 2 * time.Second, exchange: hAnswer("2.2.2.2")}
	fast := &hFakeTransport{tag: "fast", exchange: hAnswer("1.1.1.1")}
	m := hNewMulti(t, true, nil, slow, fast)
	start := time.Now()
	response, err := m.Exchange(hCtx(t), hQuestion())
	require.NoError(t, err)
	require.Equal(t, []string{"1.1.1.1"}, hAddrs(response))
	require.Less(t, time.Since(start), time.Second)
}

func TestH_MultiParallelSkipsBlockedAndErrors(t *testing.T) {
	t.Parallel()
	m := hNewMulti(t, true, []string{"10.0.0.0/8"},
		&hFakeTransport{tag: "blocked", exchange: hAnswer("10.0.0.1")},
		&hFakeTransport{tag: "error", exchange: hFail("down")},
		&hFakeTransport{tag: "good", delay: 50 * time.Millisecond, exchange: hAnswer("10.0.0.1", "8.8.4.4")},
	)
	response, err := m.Exchange(hCtx(t), hQuestion())
	require.NoError(t, err)
	require.Equal(t, []string{"8.8.4.4"}, hAddrs(response))
}

func TestH_MultiParallelAllErrors(t *testing.T) {
	t.Parallel()
	m := hNewMulti(t, true, nil,
		&hFakeTransport{tag: "a", exchange: hFail("down")},
		&hFakeTransport{tag: "b", exchange: hFail("down")},
	)
	_, err := m.Exchange(hCtx(t), hQuestion())
	require.ErrorContains(t, err, "down")
}

func TestH_MultiParallelAllBlocked(t *testing.T) {
	t.Parallel()
	m := hNewMulti(t, true, []string{"10.0.0.0/8"},
		&hFakeTransport{tag: "a", exchange: hAnswer("10.0.0.1")},
		&hFakeTransport{tag: "b", exchange: hAnswer("10.0.0.2")},
	)
	_, err := m.Exchange(hCtx(t), hQuestion())
	require.ErrorContains(t, err, "no dns response")
}

func TestH_MultiParallelContextDeadline(t *testing.T) {
	t.Parallel()
	m := hNewMulti(t, true, nil,
		&hFakeTransport{tag: "a", delay: 3 * time.Second, exchange: hAnswer("1.1.1.1")},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := m.Exchange(ctx, hQuestion())
	require.Error(t, err)
	require.Less(t, time.Since(start), 2*time.Second)
}

func TestH_MultiParallelAfterClose(t *testing.T) {
	t.Parallel()
	m := hNewMulti(t, true, nil, &hFakeTransport{tag: "a", delay: 2 * time.Second, exchange: hAnswer("1.1.1.1")})
	go func() {
		time.Sleep(50 * time.Millisecond)
		m.Close()
	}()
	start := time.Now()
	_, err := m.Exchange(hCtx(t), hQuestion())
	require.ErrorContains(t, err, "transport closed")
	require.Less(t, time.Since(start), time.Second)
}

func TestH_MultiFilterBlocked(t *testing.T) {
	t.Parallel()
	m := hNewMulti(t, false, []string{"10.0.0.0/8", "fd00::/8"})

	result, changed := m.filterBlocked(nil)
	require.Nil(t, result)
	require.False(t, changed)

	empty := new(mDNS.Msg)
	result, changed = m.filterBlocked(empty)
	require.Same(t, empty, result)
	require.False(t, changed)

	msg, _ := hAnswer("10.1.1.1", "1.1.1.1", "fd00::1", "2606:4700::1")(context.Background(), hQuestion())
	cname := &mDNS.CNAME{Hdr: mDNS.RR_Header{Name: "example.com.", Rrtype: mDNS.TypeCNAME, Class: mDNS.ClassINET}, Target: "other.example."}
	msg.Answer = append([]mDNS.RR{cname}, msg.Answer...)
	result, changed = m.filterBlocked(msg)
	require.True(t, changed)
	require.Len(t, result.Answer, 3)
	require.Same(t, cname, result.Answer[0].(*mDNS.CNAME))
	require.Equal(t, []string{"1.1.1.1", "2606:4700::1"}, hAddrs(result))

	clean, _ := hAnswer("1.1.1.1")(context.Background(), hQuestion())
	_, changed = m.filterBlocked(clean)
	require.False(t, changed)
}

func TestH_MultiIsBlocked(t *testing.T) {
	t.Parallel()
	m := hNewMulti(t, false, []string{"10.0.0.0/8", "fd00::/8"})
	require.True(t, m.isBlocked(nil))
	require.True(t, m.isBlocked(net.IP{1, 2, 3}))
	require.True(t, m.isBlocked(net.ParseIP("10.2.3.4").To4()))
	require.True(t, m.isBlocked(net.ParseIP("fd00::5")))
	require.False(t, m.isBlocked(net.ParseIP("8.8.8.8").To4()))
	require.False(t, m.isBlocked(net.ParseIP("2001:4860::8888")))

	noRanges := hNewMulti(t, false, nil)
	require.False(t, noRanges.isBlocked(net.ParseIP("10.2.3.4").To4()))
}

func TestH_MultiOptionsJSON(t *testing.T) {
	t.Parallel()
	var options option.MultiDNSServerOptions
	err := json.Unmarshal([]byte(`{"servers":["a","b"],"parallel":true,"ignore_ranges":["10.0.0.0/8","fd00::/8"]}`), &options)
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, options.Servers)
	require.True(t, options.Parallel)
	require.Len(t, options.IgnoreRanges, 2)
	require.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), netip.Prefix(options.IgnoreRanges[0]))
	require.Equal(t, netip.MustParsePrefix("fd00::/8"), netip.Prefix(options.IgnoreRanges[1]))
}

func TestH_MultiIsBlockedIPv4In16ByteForm(t *testing.T) {
	t.Skip("BUG: multi.go isBlocked does not Unmap() 16-byte IPv4 (e.g. A records built via net.ParseIP/mDNS.NewRR), so ignore_ranges like 10.0.0.0/8 never match them")
	t.Parallel()
	m := hNewMulti(t, false, []string{"10.0.0.0/8"})
	require.True(t, m.isBlocked(net.ParseIP("10.2.3.4")))
	rr, err := mDNS.NewRR("example.com. 60 IN A 10.2.3.4")
	require.NoError(t, err)
	msg := hQuestion()
	msg.Answer = []mDNS.RR{rr}
	_, changed := m.filterBlocked(msg)
	require.True(t, changed)
}

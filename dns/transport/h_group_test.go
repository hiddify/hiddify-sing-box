package transport

import (
	"context"
	"errors"
	"github.com/sagernet/sing-box/adapter/htest"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type hGroupMember struct {
	adapter.DNSTransport
	tag      string
	typ      string
	calls    atomic.Int32
	exchange func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error)
	detour   string
}

// References is the member's detour, as a remote DNS server gives it.
func (m *hGroupMember) References() []string {
	if m.detour == "" {
		return nil
	}
	return []string{m.detour}
}

// hStatusOutbound is an outbound or endpoint with the status a test sets.
type hStatusOutbound struct {
	adapter.Outbound
	tag    string
	status adapter.Status
}

func (o *hStatusOutbound) Tag() string {
	return o.tag
}

func (o *hStatusOutbound) Status() adapter.Status {
	return o.status
}

// hGroupOutbound is a ready group (a selector) using selected.
type hGroupOutbound struct {
	adapter.OutboundGroup
	tag      string
	selected adapter.Outbound
}

func (g *hGroupOutbound) Tag() string {
	return g.tag
}

func (g *hGroupOutbound) Status() adapter.Status {
	return adapter.StatusReady
}

func (g *hGroupOutbound) Selected(string) adapter.Outbound {
	return g.selected
}

type hOutboundManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m hOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.outbounds[tag]
	return outbound, loaded
}

func (m *hGroupMember) Tag() string {
	return m.tag
}

func (m *hGroupMember) Type() string {
	if m.typ == "" {
		return C.DNSTypeUDP
	}
	return m.typ
}

func (m *hGroupMember) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	m.calls.Add(1)
	go func() {
		callback(m.exchange(ctx, message))
	}()
}

func hMember(tag string, exchange func(context.Context, *mDNS.Msg) (*mDNS.Msg, error)) *hGroupMember {
	return &hGroupMember{tag: tag, exchange: exchange}
}

func hReply(addresses ...string) func(context.Context, *mDNS.Msg) (*mDNS.Msg, error) {
	return func(_ context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		response := new(mDNS.Msg).SetReply(message)
		for _, address := range addresses {
			addr := netip.MustParseAddr(address)
			header := mDNS.RR_Header{Name: "example.com.", Class: mDNS.ClassINET, Ttl: 60}
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

func hDelayed(delay time.Duration, exchange func(context.Context, *mDNS.Msg) (*mDNS.Msg, error)) func(context.Context, *mDNS.Msg) (*mDNS.Msg, error) {
	return func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		select {
		case <-time.After(delay):
			return exchange(ctx, message)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func hFail(err error) func(context.Context, *mDNS.Msg) (*mDNS.Msg, error) {
	return func(context.Context, *mDNS.Msg) (*mDNS.Msg, error) {
		return nil, err
	}
}

func hHang(ctx context.Context, _ *mDNS.Msg) (*mDNS.Msg, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func hGroupContext(members ...*hGroupMember) context.Context {
	transports := make(map[string]adapter.DNSTransport, len(members))
	for _, member := range members {
		transports[member.tag] = member
	}
	return service.ContextWith[adapter.DNSTransportManager](context.Background(), groupTestManager{transports: transports})
}

func hNewGroup(t *testing.T, options option.GroupDNSServerOptions, members ...*hGroupMember) *GroupTransport {
	t.Helper()
	if options.Servers == nil {
		for _, member := range members {
			options.Servers = append(options.Servers, member.tag)
		}
	}
	transport, err := NewGroup(hGroupContext(members...), log.NewNOPFactory().Logger(), "group", options)
	require.NoError(t, err)
	return transport.(*GroupTransport)
}

func hPrefixes(prefixes ...string) []badoption.Prefix {
	result := make([]badoption.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		result = append(result, badoption.Prefix(netip.MustParsePrefix(prefix)))
	}
	return result
}

func hExchange(t *testing.T, transport adapter.DNSTransport) (*mDNS.Msg, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return transport.Exchange(ctx, new(mDNS.Msg).SetQuestion("example.com.", mDNS.TypeA))
}

func hAnswerIPs(response *mDNS.Msg) []string {
	var result []string
	for _, record := range response.Answer {
		switch answer := record.(type) {
		case *mDNS.A:
			result = append(result, answer.A.String())
		case *mDNS.AAAA:
			result = append(result, answer.AAAA.String())
		}
	}
	return result
}

var hErrMember = errors.New("member failed")

func TestH_GroupModeParsing(t *testing.T) {
	member := hMember("a", hReply("1.1.1.1"))
	require.Nil(t, hNewGroup(t, option.GroupDNSServerOptions{}, member).sequential)
	require.Nil(t, hNewGroup(t, option.GroupDNSServerOptions{Mode: C.DNSGroupModeParallel}, member).sequential)
	require.NotNil(t, hNewGroup(t, option.GroupDNSServerOptions{Mode: C.DNSGroupModeSequential}, member).sequential)

	_, err := NewGroup(hGroupContext(member), log.NewNOPFactory().Logger(), "group", option.GroupDNSServerOptions{Servers: []string{"a"}, Mode: "random"})
	require.ErrorContains(t, err, "unknown group mode: random")
	_, err = NewGroup(hGroupContext(member), log.NewNOPFactory().Logger(), "group", option.GroupDNSServerOptions{})
	require.ErrorContains(t, err, "missing servers")
}

func TestH_GroupOptionsJSON(t *testing.T) {
	var options option.GroupDNSServerOptions
	require.NoError(t, json.Unmarshal([]byte(`{"servers":["a","b"],"mode":"sequential","ignore_ranges":["10.0.0.0/8","fd00::/8"]}`), &options))
	require.Equal(t, []string{"a", "b"}, options.Servers)
	require.Equal(t, C.DNSGroupModeSequential, options.Mode)
	require.Equal(t, hPrefixes("10.0.0.0/8", "fd00::/8"), options.IgnoreRanges)
	content, err := json.Marshal(options)
	require.NoError(t, err)
	require.JSONEq(t, `{"servers":["a","b"],"mode":"sequential","ignore_ranges":["10.0.0.0/8","fd00::/8"]}`, string(content))
}

func TestH_GroupMultiAlias(t *testing.T) {
	member := hMember("a", hReply("1.1.1.1"))
	for _, parallel := range []bool{false, true} {
		transport, err := NewMulti(hGroupContext(member), log.NewNOPFactory().Logger(), "legacy", option.MultiDNSServerOptions{
			Servers:      []string{"a"},
			Parallel:     parallel,
			IgnoreRanges: hPrefixes("10.0.0.0/8"),
		})
		require.NoError(t, err)
		group := transport.(*GroupTransport)
		require.Equal(t, C.DNSTypeMulti, group.Type())
		require.Equal(t, "legacy", group.Tag())
		require.Equal(t, !parallel, group.sequential != nil)
		require.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, group.ignoreRanges)
	}
	_, err := NewMulti(hGroupContext(member), log.NewNOPFactory().Logger(), "legacy", option.MultiDNSServerOptions{})
	require.ErrorContains(t, err, "missing servers")
}

func TestH_GroupStartValidation(t *testing.T) {
	plain := hMember("plain", hReply("1.1.1.1"))
	nestedGroup := &hGroupMember{tag: "nested-group", typ: C.DNSTypeGroup}
	nestedMulti := &hGroupMember{tag: "nested-multi", typ: C.DNSTypeMulti}
	fakeIP := &hGroupMember{tag: "fake", typ: C.DNSTypeFakeIP}
	members := []*hGroupMember{plain, nestedGroup, nestedMulti, fakeIP}

	require.NoError(t, htest.Start(hNewGroup(t, option.GroupDNSServerOptions{Servers: []string{"plain"}}, members...), adapter.StartStateStart))
	require.NoError(t, htest.Start(hNewGroup(t, option.GroupDNSServerOptions{Servers: []string{"missing"}}, members...), adapter.StartStateInitialize))
	require.ErrorContains(t, htest.Start(hNewGroup(t, option.GroupDNSServerOptions{Servers: []string{"missing"}}, members...), adapter.StartStateStart), "DNS server not found: missing")
	require.ErrorContains(t, htest.Start(hNewGroup(t, option.GroupDNSServerOptions{Servers: []string{"nested-group"}}, members...), adapter.StartStateStart), "cannot contain another group")
	require.ErrorContains(t, htest.Start(hNewGroup(t, option.GroupDNSServerOptions{Servers: []string{"nested-multi"}}, members...), adapter.StartStateStart), "cannot contain another group")
	require.ErrorContains(t, htest.Start(hNewGroup(t, option.GroupDNSServerOptions{Servers: []string{"fake"}}, members...), adapter.StartStateStart), "cannot contain fakeip")
}

func TestH_GroupSequentialStopsAtFirstAnswer(t *testing.T) {
	first := hMember("first", hReply("1.1.1.1"))
	second := hMember("second", hReply("2.2.2.2"))
	group := hNewGroup(t, option.GroupDNSServerOptions{Mode: C.DNSGroupModeSequential}, first, second)
	response, err := hExchange(t, group)
	require.NoError(t, err)
	require.Equal(t, []string{"1.1.1.1"}, hAnswerIPs(response))
	require.EqualValues(t, 1, first.calls.Load())
	require.EqualValues(t, 0, second.calls.Load())
}

func TestH_GroupSequentialFallsThroughErrors(t *testing.T) {
	first := hMember("first", hFail(hErrMember))
	second := hMember("second", hReply("2.2.2.2"))
	group := hNewGroup(t, option.GroupDNSServerOptions{Mode: C.DNSGroupModeSequential}, first, second)
	response, err := hExchange(t, group)
	require.NoError(t, err)
	require.Equal(t, []string{"2.2.2.2"}, hAnswerIPs(response))
}

func TestH_GroupSequentialReturnsLastError(t *testing.T) {
	lastErr := errors.New("last failed")
	group := hNewGroup(t, option.GroupDNSServerOptions{Mode: C.DNSGroupModeSequential},
		hMember("first", hFail(hErrMember)), hMember("second", hFail(lastErr)))
	_, err := hExchange(t, group)
	require.ErrorIs(t, err, lastErr)
}

func TestH_GroupSequentialSkipsIgnoredRanges(t *testing.T) {
	poisoned := hMember("poisoned", hReply("10.10.34.35"))
	clean := hMember("clean", hReply("93.184.216.34"))
	group := hNewGroup(t, option.GroupDNSServerOptions{Mode: C.DNSGroupModeSequential, IgnoreRanges: hPrefixes("10.0.0.0/8")}, poisoned, clean)
	response, err := hExchange(t, group)
	require.NoError(t, err)
	require.Equal(t, []string{"93.184.216.34"}, hAnswerIPs(response))
	require.EqualValues(t, 1, clean.calls.Load())
}

func TestH_GroupSequentialEmptyResponseIsFallback(t *testing.T) {
	empty := hMember("empty", hReply())
	failed := hMember("failed", hFail(hErrMember))
	group := hNewGroup(t, option.GroupDNSServerOptions{Mode: C.DNSGroupModeSequential}, empty, failed)
	response, err := hExchange(t, group)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Empty(t, response.Answer)
	require.EqualValues(t, 1, failed.calls.Load(), "an empty response must not stop the search for an answer")

	answered := hMember("answered", hReply("3.3.3.3"))
	group = hNewGroup(t, option.GroupDNSServerOptions{Mode: C.DNSGroupModeSequential}, hMember("empty", hReply()), answered)
	response, err = hExchange(t, group)
	require.NoError(t, err)
	require.Equal(t, []string{"3.3.3.3"}, hAnswerIPs(response))
}

func TestH_GroupSequentialAllIgnored(t *testing.T) {
	group := hNewGroup(t, option.GroupDNSServerOptions{Mode: C.DNSGroupModeSequential, IgnoreRanges: hPrefixes("10.0.0.0/8")},
		hMember("a", hReply("10.0.0.1")), hMember("b", hReply("10.0.0.2")))
	_, err := hExchange(t, group)
	require.ErrorContains(t, err, "all DNS servers failed")
}

func TestH_GroupSequentialMissingServer(t *testing.T) {
	answered := hMember("answered", hReply("4.4.4.4"))
	group := hNewGroup(t, option.GroupDNSServerOptions{Mode: C.DNSGroupModeSequential, Servers: []string{"missing", "answered"}}, answered)
	response, err := hExchange(t, group)
	require.NoError(t, err)
	require.Equal(t, []string{"4.4.4.4"}, hAnswerIPs(response))
}

func TestH_GroupSequentialHonorsCancellation(t *testing.T) {
	silent := hMember("silent", hHang)
	next := hMember("next", hReply("5.5.5.5"))
	group := hNewGroup(t, option.GroupDNSServerOptions{Mode: C.DNSGroupModeSequential}, silent, next)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := group.Exchange(ctx, new(mDNS.Msg).SetQuestion("example.com.", mDNS.TypeA))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.EqualValues(t, 0, next.calls.Load())
}

func TestH_GroupNilResponseIsError(t *testing.T) {
	for _, mode := range []string{C.DNSGroupModeSequential, C.DNSGroupModeParallel} {
		nilMember := hMember("nil", func(context.Context, *mDNS.Msg) (*mDNS.Msg, error) { return nil, nil })
		group := hNewGroup(t, option.GroupDNSServerOptions{Mode: mode}, nilMember)
		_, err := hExchange(t, group)
		require.ErrorContains(t, err, "empty response from nil", mode)

		group = hNewGroup(t, option.GroupDNSServerOptions{Mode: mode},
			hMember("nil", func(context.Context, *mDNS.Msg) (*mDNS.Msg, error) { return nil, nil }), hMember("ok", hReply("6.6.6.6")))
		response, err := hExchange(t, group)
		require.NoError(t, err, mode)
		require.Equal(t, []string{"6.6.6.6"}, hAnswerIPs(response), mode)
	}
}

func TestH_GroupParallelFastestAnswerWins(t *testing.T) {
	slow := hMember("slow", hDelayed(time.Second, hReply("1.1.1.1")))
	fast := hMember("fast", hReply("2.2.2.2"))
	group := hNewGroup(t, option.GroupDNSServerOptions{}, slow, fast)
	start := time.Now()
	response, err := hExchange(t, group)
	require.NoError(t, err)
	require.Equal(t, []string{"2.2.2.2"}, hAnswerIPs(response))
	require.Less(t, time.Since(start), 500*time.Millisecond)
}

func TestH_GroupParallelIgnoredFastResponseLoses(t *testing.T) {
	poisoned := hMember("poisoned", hReply("10.10.34.36"))
	clean := hMember("clean", hDelayed(50*time.Millisecond, hReply("93.184.216.34")))
	group := hNewGroup(t, option.GroupDNSServerOptions{IgnoreRanges: hPrefixes("10.0.0.0/8")}, poisoned, clean)
	response, err := hExchange(t, group)
	require.NoError(t, err)
	require.Equal(t, []string{"93.184.216.34"}, hAnswerIPs(response))
}

func TestH_GroupParallelEmptyResponseLosesToAnswer(t *testing.T) {
	empty := hMember("empty", hReply())
	answered := hMember("answered", hDelayed(50*time.Millisecond, hReply("7.7.7.7")))
	group := hNewGroup(t, option.GroupDNSServerOptions{}, empty, answered)
	response, err := hExchange(t, group)
	require.NoError(t, err)
	require.Equal(t, []string{"7.7.7.7"}, hAnswerIPs(response))
}

func TestH_GroupParallelAllEmptyReturnsFallback(t *testing.T) {
	group := hNewGroup(t, option.GroupDNSServerOptions{}, hMember("a", hReply()), hMember("b", hFail(hErrMember)))
	response, err := hExchange(t, group)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Empty(t, response.Answer)
}

func TestH_GroupParallelFallbackOnDeadline(t *testing.T) {
	group := hNewGroup(t, option.GroupDNSServerOptions{}, hMember("empty", hReply()), hMember("silent", hHang))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	response, err := group.Exchange(ctx, new(mDNS.Msg).SetQuestion("example.com.", mDNS.TypeA))
	require.NoError(t, err)
	require.NotNil(t, response)
}

func TestH_GroupParallelAllErrorsReturnsFirst(t *testing.T) {
	lateErr := errors.New("late failure")
	group := hNewGroup(t, option.GroupDNSServerOptions{},
		hMember("early", hFail(hErrMember)), hMember("late", hDelayed(50*time.Millisecond, hFail(lateErr))))
	_, err := hExchange(t, group)
	require.ErrorIs(t, err, hErrMember)
}

func TestH_GroupParallelAllIgnored(t *testing.T) {
	group := hNewGroup(t, option.GroupDNSServerOptions{IgnoreRanges: hPrefixes("10.0.0.0/8", "fd00::/8")},
		hMember("a", hReply("10.0.0.1")), hMember("b", hReply("fd00::1")))
	_, err := hExchange(t, group)
	require.ErrorContains(t, err, "all DNS servers failed")
}

func TestH_GroupFilterIgnored(t *testing.T) {
	group := hNewGroup(t, option.GroupDNSServerOptions{IgnoreRanges: hPrefixes("10.0.0.0/8", "fd00::/8")}, hMember("a", hReply()))
	message := new(mDNS.Msg).SetQuestion("example.com.", mDNS.TypeA)
	message.Answer = []mDNS.RR{
		&mDNS.CNAME{Hdr: mDNS.RR_Header{Name: "example.com.", Rrtype: mDNS.TypeCNAME, Class: mDNS.ClassINET}, Target: "cdn.example.com."},
		&mDNS.A{Hdr: mDNS.RR_Header{Name: "cdn.example.com.", Rrtype: mDNS.TypeA, Class: mDNS.ClassINET}, A: net.ParseIP("10.1.2.3")},
		&mDNS.A{Hdr: mDNS.RR_Header{Name: "cdn.example.com.", Rrtype: mDNS.TypeA, Class: mDNS.ClassINET}, A: net.ParseIP("93.184.216.34")},
		&mDNS.AAAA{Hdr: mDNS.RR_Header{Name: "cdn.example.com.", Rrtype: mDNS.TypeAAAA, Class: mDNS.ClassINET}, AAAA: net.ParseIP("fd00::5")},
	}
	filtered, changed := group.filterIgnored(message)
	require.True(t, changed)
	require.Len(t, filtered.Answer, 2)
	require.IsType(t, &mDNS.CNAME{}, filtered.Answer[0])
	require.Equal(t, "93.184.216.34", filtered.Answer[1].(*mDNS.A).A.String())
	require.Len(t, message.Answer, 4, "input message must not be modified")

	unchanged, changed := group.filterIgnored(filtered)
	require.False(t, changed)
	require.Same(t, filtered, unchanged)

	noRanges := hNewGroup(t, option.GroupDNSServerOptions{}, hMember("a", hReply()))
	same, changed := noRanges.filterIgnored(message)
	require.False(t, changed)
	require.Same(t, message, same)
}

func TestH_GroupIsIgnored(t *testing.T) {
	group := hNewGroup(t, option.GroupDNSServerOptions{IgnoreRanges: hPrefixes("10.0.0.0/8", "2001:db8::/32")}, hMember("a", hReply()))
	require.True(t, group.isIgnored(net.ParseIP("10.2.3.4")), "16-byte IPv4 form must be unmapped")
	require.True(t, group.isIgnored(net.IPv4(10, 2, 3, 4).To4()))
	require.True(t, group.isIgnored(net.ParseIP("2001:db8::1")))
	require.False(t, group.isIgnored(net.ParseIP("11.0.0.1")))
	require.False(t, group.isIgnored(net.ParseIP("2001:db9::1")))
	require.True(t, group.isIgnored(nil), "invalid address is ignored")
}

// A server that failed loses a point when another server answers, so the one that answers is
// asked first from then on; a server keeps its listed place while the scores are equal.
func TestH_GroupSequentialScoresOrderTheServers(t *testing.T) {
	first := hMember("first", hFail(hErrMember))
	second := hMember("second", hReply("2.2.2.2"))
	group := hNewGroup(t, option.GroupDNSServerOptions{Mode: C.DNSGroupModeSequential}, first, second)
	for i := 0; i < 3; i++ {
		response, err := hExchange(t, group)
		require.NoError(t, err)
		require.Equal(t, []string{"2.2.2.2"}, hAnswerIPs(response))
	}
	require.EqualValues(t, 1, first.calls.Load(), "the failed server is asked after the one that answers")
	require.EqualValues(t, 3, second.calls.Load())
	require.Equal(t, -1, group.sequential.score("first"))
	require.Equal(t, 3, group.sequential.score("second"))

	// the network changed: the scores are forgotten and the first server is first again
	group.Reset()
	first.exchange = hReply("1.1.1.1")
	response, err := hExchange(t, group)
	require.NoError(t, err)
	require.Equal(t, []string{"1.1.1.1"}, hAnswerIPs(response))
	require.EqualValues(t, 3, second.calls.Load(), "second was not asked after the reset")
}

// No server loses a point for a query no server answers: that says more about the network.
func TestH_GroupSequentialNoAnswerScoresNothing(t *testing.T) {
	first := hMember("first", hFail(hErrMember))
	second := hMember("second", hFail(hErrMember))
	group := hNewGroup(t, option.GroupDNSServerOptions{Mode: C.DNSGroupModeSequential}, first, second)
	for i := 0; i < 3; i++ {
		_, err := hExchange(t, group)
		require.Error(t, err)
	}
	require.Equal(t, 0, group.sequential.score("first"))
	require.Equal(t, 0, group.sequential.score("second"))
	require.EqualValues(t, 3, first.calls.Load(), "the order stays as listed")
}

// Scores stay within -10 and 10, and one answer lifts a server to at least 1, ahead of every
// server that did not answer.
func TestH_GroupSequentialScoreBounds(t *testing.T) {
	sequential := newGroupSequential(option.GroupDNSServerOptions{Mode: C.DNSGroupModeSequential})
	for i := 0; i < 15; i++ {
		sequential.record("good", []string{"bad"})
	}
	require.Equal(t, 10, sequential.score("good"))
	require.Equal(t, -10, sequential.score("bad"))

	sequential.record("bad", nil)
	require.Equal(t, 1, sequential.score("bad"), "the first answer after failing gives at least 1")
	sequential.record("bad", nil)
	require.Equal(t, 2, sequential.score("bad"))

	sequential.record("", []string{"good"})
	require.Equal(t, 10, sequential.score("good"), "no answer: no point lost")

	require.Equal(t, []string{"good", "bad", "new"}, sequential.order([]string{"new", "bad", "good"}))
}

// A server whose detour is not ready, as WARP still connecting, is not asked and loses no point;
// once the detour is ready, it is asked and a failure costs one.
func TestH_GroupSequentialDetourNotReadyIsNoFailure(t *testing.T) {
	hop := &hStatusOutbound{status: adapter.StatusConnecting}
	viaHop := hMember("via-hop", hFail(errors.New("endpoint not initialized")))
	viaHop.detour = "hop"
	profile := hMember("profile", hReply("4.4.4.4"))
	ctx := service.ContextWith[adapter.OutboundManager](hGroupContext(viaHop, profile), hOutboundManager{outbounds: map[string]adapter.Outbound{"hop": hop}})
	transport, err := NewGroup(ctx, log.NewNOPFactory().Logger(), "group", option.GroupDNSServerOptions{Mode: C.DNSGroupModeSequential, Servers: []string{"via-hop", "profile"}})
	require.NoError(t, err)
	group := transport.(*GroupTransport)

	response, err := hExchange(t, group)
	require.NoError(t, err)
	require.Equal(t, []string{"4.4.4.4"}, hAnswerIPs(response))
	require.EqualValues(t, 0, viaHop.calls.Load(), "a server behind a detour that is not ready is not asked")
	require.Equal(t, 0, group.sequential.score("via-hop"))
	require.Equal(t, 1, group.sequential.score("profile"))

	hop.status = adapter.StatusReady
	group.Reset()
	_, err = hExchange(t, group)
	require.NoError(t, err)
	require.EqualValues(t, 1, viaHop.calls.Load())
	require.Equal(t, -1, group.sequential.score("via-hop"), "with the detour ready the failure counts")

	// no server has a ready detour: the query fails at once
	hop.status = adapter.StatusConnecting
	only, err := NewGroup(ctx, log.NewNOPFactory().Logger(), "only-hop", option.GroupDNSServerOptions{Mode: C.DNSGroupModeSequential, Servers: []string{"via-hop"}})
	require.NoError(t, err)
	_, err = hExchange(t, only)
	require.ErrorContains(t, err, "has a ready detour")
	require.EqualValues(t, 1, viaHop.calls.Load())
}

// A selector is ready itself; the proxy selected in it decides, through nested groups too. A
// group that has not picked one counts as ready.
func TestH_GroupSequentialDetourGroupFollowsSelected(t *testing.T) {
	proxy := &hStatusOutbound{tag: "proxy", status: adapter.StatusConnecting}
	inner := &hGroupOutbound{tag: "auto", selected: proxy}
	selector := &hGroupOutbound{tag: "select", selected: inner}
	empty := &hGroupOutbound{tag: "empty"}
	viaSelect := hMember("via-select", hReply("6.6.6.6"))
	viaSelect.detour = "select"
	viaEmpty := hMember("via-empty", hReply("7.7.7.7"))
	viaEmpty.detour = "empty"
	outbounds := map[string]adapter.Outbound{"proxy": proxy, "auto": inner, "select": selector, "empty": empty}
	ctx := service.ContextWith[adapter.OutboundManager](hGroupContext(viaSelect, viaEmpty), hOutboundManager{outbounds: outbounds})
	transport, err := NewGroup(ctx, log.NewNOPFactory().Logger(), "group", option.GroupDNSServerOptions{Mode: C.DNSGroupModeSequential, Servers: []string{"via-select", "via-empty"}})
	require.NoError(t, err)
	group := transport.(*GroupTransport)

	response, err := hExchange(t, group)
	require.NoError(t, err)
	require.Equal(t, []string{"7.7.7.7"}, hAnswerIPs(response))
	require.EqualValues(t, 0, viaSelect.calls.Load(), "the proxy selected in the selector's urltest is connecting")

	proxy.status = adapter.StatusReady
	group.Reset()
	response, err = hExchange(t, group)
	require.NoError(t, err)
	require.Equal(t, []string{"6.6.6.6"}, hAnswerIPs(response))
}

// A server that answers without an address neither gains nor loses.
func TestH_GroupSequentialEmptyAnswerKeepsScore(t *testing.T) {
	empty := hMember("empty", hReply())
	next := hMember("next", hReply("3.3.3.3"))
	group := hNewGroup(t, option.GroupDNSServerOptions{Mode: C.DNSGroupModeSequential}, empty, next)
	_, err := hExchange(t, group)
	require.NoError(t, err)
	require.Equal(t, 0, group.sequential.score("empty"))
	require.Equal(t, 1, group.sequential.score("next"))
}

// A server that hangs gets a share of the query's time, not all of it: the servers behind it are
// still asked and one of them answers within the query's deadline.
func TestH_GroupSequentialBoundsAHangingServer(t *testing.T) {
	silent := hMember("silent", hHang)
	next := hMember("next", hReply("5.5.5.5"))
	group := hNewGroup(t, option.GroupDNSServerOptions{Mode: C.DNSGroupModeSequential, MemberTimeout: badoption.Duration(100 * time.Millisecond)}, silent, next)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	response, err := group.Exchange(ctx, new(mDNS.Msg).SetQuestion("example.com.", mDNS.TypeA))
	require.NoError(t, err)
	require.Equal(t, []string{"5.5.5.5"}, hAnswerIPs(response))
	require.Less(t, time.Since(start), 600*time.Millisecond, "the hanging server was given up on after member_timeout")
	require.EqualValues(t, 1, next.calls.Load())
}

// Without member_timeout the time left is shared, with a floor: a short deadline gives the first
// server all of it, as before.
func TestH_GroupSequentialSharesTheDeadline(t *testing.T) {
	sequential := newGroupSequential(option.GroupDNSServerOptions{Mode: C.DNSGroupModeSequential})
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
	defer cancel()
	require.InDelta(t, 3*time.Second, sequential.budget(ctx, 3), float64(100*time.Millisecond))
	require.InDelta(t, defaultSequentialMemberFloor, sequential.budget(ctx, 9), float64(100*time.Millisecond))
	short, cancelShort := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelShort()
	require.LessOrEqual(t, sequential.budget(short, 2), 50*time.Millisecond)
}

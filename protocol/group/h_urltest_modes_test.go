package group

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// hProbeOutbound reaches a local HTTP server for any destination, after delay. A dead one fails
// with a timeout, a refusing one with a refused connection; blocked hosts always time out.
type hProbeOutbound struct {
	tag     string
	server  string
	delay   time.Duration
	dead    atomic.Bool
	refuse  atomic.Bool
	blocked map[string]bool
	dials   atomic.Int32
}

func (o *hProbeOutbound) Type() string           { return "probe" }
func (o *hProbeOutbound) Tag() string            { return o.tag }
func (o *hProbeOutbound) Network() []string      { return []string{N.NetworkTCP, N.NetworkUDP} }
func (o *hProbeOutbound) Dependencies() []string { return nil }
func (o *hProbeOutbound) Status() adapter.Status { return adapter.StatusReady }

func (o *hProbeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.dials.Add(1)
	if o.refuse.Load() {
		return nil, syscall.ECONNREFUSED
	}
	if o.dead.Load() || o.blocked[destination.AddrString()] {
		return nil, context.DeadlineExceeded
	}
	select {
	case <-time.After(o.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", o.server)
}

func (o *hProbeOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}

func hProbeServer(t *testing.T) string {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	return server.Listener.Addr().String()
}

func hProbe(t *testing.T, server string, tag string, delay time.Duration) *hProbeOutbound {
	return &hProbeOutbound{tag: tag, server: server, delay: delay}
}

func hURLTest(t *testing.T, options option.URLTestOutboundOptions, members ...*hProbeOutbound) *URLTest {
	t.Helper()
	ctx := service.ContextWithDefaultRegistry(context.Background())
	ctx = pause.WithDefaultManager(ctx)
	ctx = service.ContextWithPtr(ctx, urltest.NewHistoryStorage())
	manager := &hOutboundManager{outbounds: map[string]adapter.Outbound{}}
	for _, member := range members {
		manager.outbounds[member.tag] = member
		options.Outbounds = append(options.Outbounds, member.tag)
	}
	if options.URL == "" && len(options.URLs) == 0 {
		options.URL = "http://probe.test/generate_204"
	}
	created, err := NewURLTest(ctx, nil, log.NewNOPFactory().Logger(), "urltest", options)
	require.NoError(t, err)
	group := created.(*URLTest)
	group.outbound = manager
	require.NoError(t, group.Start(adapter.StartStateStart, nil))
	t.Cleanup(func() { group.group.Close() })
	return group
}

func hSelected(group *URLTest) string {
	return group.Selected(N.NetworkTCP).Tag()
}

func hGroupDial(group *URLTest) error {
	conn, err := group.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:80"))
	if err == nil {
		conn.Close()
	}
	return err
}

// A member is up when any of the test URLs answers.
func TestH_URLTestURLs(t *testing.T) {
	server := hProbeServer(t)
	member := hProbe(t, server, "a", 0)
	member.blocked = map[string]bool{"blocked.test": true}
	group := hURLTest(t, option.URLTestOutboundOptions{URL: "http://blocked.test/", URLs: []string{"http://open.test/"}}, member)
	result, err := group.URLTest(context.Background())
	require.NoError(t, err)
	require.Contains(t, result, "a")

	only := hURLTest(t, option.URLTestOutboundOptions{URL: "http://blocked.test/"}, member)
	result, err = only.URLTest(context.Background())
	require.NoError(t, err)
	require.NotContains(t, result, "a")

	require.Equal(t, []string{"http://a/", "http://b/"}, testLinks("http://a/", []string{"http://b/", "http://a/", ""}))
	require.Equal(t, []string{""}, testLinks("", nil))
}

// A dead-path dial fails over once to the best other member and moves the selection there.
func TestH_URLTestPenaltyFailover(t *testing.T) {
	server := hProbeServer(t)
	fast, slow := hProbe(t, server, "fast", 5*time.Millisecond), hProbe(t, server, "slow", 60*time.Millisecond)
	group := hURLTest(t, option.URLTestOutboundOptions{}, fast, slow)
	_, err := group.URLTest(context.Background())
	require.NoError(t, err)
	require.Equal(t, "fast", hSelected(group))

	fast.dead.Store(true)
	require.NoError(t, hGroupDial(group), "the second try goes through slow")
	require.Equal(t, "slow", hSelected(group))
	require.EqualValues(t, 1, group.group.penaltyOf("fast"))

	fast.dead.Store(false)
	_, err = group.URLTest(context.Background())
	require.NoError(t, err)
	require.Zero(t, group.group.penaltyOf("fast"), "a test that works clears the penalty")
}

// A refused connection is the destination's answer: no penalty, no second try.
func TestH_URLTestRefusedIsNotPenalized(t *testing.T) {
	server := hProbeServer(t)
	a, b := hProbe(t, server, "a", 5*time.Millisecond), hProbe(t, server, "b", 60*time.Millisecond)
	group := hURLTest(t, option.URLTestOutboundOptions{}, a, b)
	_, err := group.URLTest(context.Background())
	require.NoError(t, err)
	a.refuse.Store(true)
	require.Error(t, hGroupDial(group))
	require.Zero(t, b.dials.Load()-1, "only b's test dial")
	require.Zero(t, group.group.penaltyOf("a"))
}

// When the fastest member has penaltyThreshold penalties, members rank by penalties first.
func TestH_URLTestPenaltyEmergency(t *testing.T) {
	server := hProbeServer(t)
	fast, slow := hProbe(t, server, "fast", 5*time.Millisecond), hProbe(t, server, "slow", 60*time.Millisecond)
	group := hURLTest(t, option.URLTestOutboundOptions{}, fast, slow)
	_, err := group.URLTest(context.Background())
	require.NoError(t, err)
	for range penaltyThreshold {
		group.group.penaltyAdd("fast")
	}
	require.Equal(t, "slow", group.group.pickForDial(N.NetworkTCP).Tag())
	group.group.penaltyReset("fast")
	require.Equal(t, "fast", group.group.pickForDial(N.NetworkTCP).Tag())
}

// failover keeps the selected member while it works, testing only it, and moves to the fastest
// when it fails.
func TestH_URLTestFailover(t *testing.T) {
	server := hProbeServer(t)
	a, b, c := hProbe(t, server, "a", 60*time.Millisecond), hProbe(t, server, "b", 5*time.Millisecond), hProbe(t, server, "c", 30*time.Millisecond)
	group := hURLTest(t, option.URLTestOutboundOptions{Mode: C.URLTestModeFailover}, a, b, c)
	group.group.CheckOutbounds(context.Background(), false)
	require.Equal(t, "b", hSelected(group), "the first choice is the fastest")

	b.delay = 45 * time.Millisecond // b is now slower than c, but within twice its delay
	dials := a.dials.Load() + c.dials.Load()
	group.group.CheckOutbounds(context.Background(), false)
	require.Equal(t, "b", hSelected(group), "kept while it works")
	require.Equal(t, dials, a.dials.Load()+c.dials.Load(), "only the selected member is tested")

	b.delay = 250 * time.Millisecond // more than twice as slow as c: degraded
	bDials := b.dials.Load()
	group.group.CheckOutbounds(context.Background(), false)
	require.Equal(t, "c", hSelected(group), "left a member that slowed down, for one more than 1.5 times faster")
	require.GreaterOrEqual(t, b.dials.Load()-bDials, int32(2), "the slow result was confirmed by a second test")
	b.delay = 5 * time.Millisecond

	b.dead.Store(true)
	group.group.CheckOutbounds(context.Background(), false)
	require.Equal(t, "c", hSelected(group), "moved to the fastest when it failed")

	_, err := NewURLTest(context.Background(), nil, log.NewNOPFactory().Logger(), "x", option.URLTestOutboundOptions{Outbounds: []string{"a"}, Mode: "unknown"})
	require.Error(t, err)
}

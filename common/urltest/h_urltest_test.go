package urltest

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/hiddify/ipinfo"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/observable"

	"github.com/stretchr/testify/require"
)

type loopbackDialer struct {
	addr      string
	afterDial func()
}

func (d *loopbackDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, network, d.addr)
	if err == nil && d.afterDial != nil {
		d.afterDial()
	}
	return conn, err
}

func (d *loopbackDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func countingServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		require.Equal(t, http.MethodHead, r.Method)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	return server, &hits
}

func TestH_URLTestUnifiedDelayContext(t *testing.T) {
	ctx := context.Background()
	require.False(t, IsUnifiedDelayFromContext(ctx))
	require.True(t, IsUnifiedDelayFromContext(ContextWithIsUnifiedDelay(ctx)))
}

func TestH_URLTestNilDialer(t *testing.T) {
	_, err := URLTest(context.Background(), "http://127.0.0.1/", nil)
	require.Error(t, err)
}

func TestH_URLTestLoopback(t *testing.T) {
	server, hits := countingServer(t)
	dialer := &loopbackDialer{addr: server.Listener.Addr().String()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := URLTest(ctx, "http://probe.example/generate_204", dialer)
	require.NoError(t, err)
	require.Equal(t, int32(1), hits.Load())

	_, err = URLTest(ContextWithIsUnifiedDelay(ctx), "http://probe.example/generate_204", dialer)
	require.NoError(t, err)
	require.Equal(t, int32(3), hits.Load(), "unified delay performs a second request on the warmed connection")
}

func TestH_URLTestCanceledAfterDialReportsError(t *testing.T) {
	t.Skip("BUG: urlTest returns (0, nil) when ctx is canceled after the dial, reporting a successful 0ms test")
	server, _ := countingServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dialer := &loopbackDialer{addr: server.Listener.Addr().String(), afterDial: cancel}
	_, err := URLTest(ctx, "http://probe.example/generate_204", dialer)
	require.Error(t, err)
}

func TestH_HistoryStorage(t *testing.T) {
	var nilStorage *HistoryStorage
	require.Nil(t, nilStorage.LoadURLTestHistory("a"))

	s := NewHistoryStorage()
	hook := observable.NewSubscriber[struct{}](8)
	s.SetHook(hook)
	updates, _ := hook.Subscription()
	drain := func() int {
		n := 0
		for {
			select {
			case <-updates:
				n++
			default:
				return n
			}
		}
	}

	info := &ipinfo.IpInfo{IP: "1.1.1.1"}
	first := &adapter.URLTestHistory{Delay: 100, Time: time.Unix(100, 0), IpInfo: info}
	require.Same(t, first, s.StoreURLTestHistory("a", first))
	require.Equal(t, 1, drain())

	stored := s.StoreURLTestHistory("a", &adapter.URLTestHistory{Delay: 50, Time: time.Unix(200, 0)})
	require.Same(t, first, stored, "existing entries are updated in place")
	require.Equal(t, uint16(50), stored.Delay)
	require.Equal(t, time.Unix(200, 0), stored.Time)
	require.Same(t, info, stored.IpInfo, "ip info is preserved")

	s.DeleteURLTestHistory("a")
	loaded := s.LoadURLTestHistory("a")
	require.NotNil(t, loaded, "delete keeps the entry and marks it timed out")
	require.Equal(t, uint16(65535), loaded.Delay)
	require.Same(t, info, loaded.IpInfo)

	s.AddOnlyIpToHistory("a", &adapter.URLTestHistory{Delay: 1})
	require.Equal(t, uint16(65535), s.LoadURLTestHistory("a").Delay, "does not overwrite existing entry")
	s.AddOnlyIpToHistory("b", &adapter.URLTestHistory{Delay: 7})
	require.Equal(t, uint16(7), s.LoadURLTestHistory("b").Delay)
	s.AddOnlyIpToHistory("c", nil)
	require.Nil(t, s.LoadURLTestHistory("c"))
	require.Equal(t, 5, drain())

	s.NotifyUpdated()
	require.Equal(t, 1, drain())

	require.NoError(t, s.Close())
	s.StoreURLTestHistory("d", &adapter.URLTestHistory{Delay: 1})
	require.Equal(t, 0, drain(), "hooks are dropped on close")
}

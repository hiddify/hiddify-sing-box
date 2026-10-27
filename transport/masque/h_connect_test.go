package masque

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/log"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"github.com/stretchr/testify/require"
)

// hLegs scripts the connects of each HTTP version: an error, a stall until the context ends,
// or a success.
type hLegs struct {
	access   sync.Mutex
	behavior map[bool]string // "ok", "fail", "stall"
	calls    []bool
}

func (l *hLegs) set(http2 bool, behavior string) {
	l.access.Lock()
	l.behavior[http2] = behavior
	l.access.Unlock()
}

func (l *hLegs) connect(ctx context.Context, _ N.Dialer, _ aTLS.Config, _ *quic.Config, _ string, endpoint net.Addr, http2 bool) (net.PacketConn, *http3.Transport, *connectip.Conn, *http.Response, error) {
	l.access.Lock()
	l.calls = append(l.calls, http2)
	behavior := l.behavior[http2]
	l.access.Unlock()
	switch behavior {
	case "ok":
		return nil, nil, &connectip.Conn{}, &http.Response{StatusCode: http.StatusOK}, nil
	case "stall":
		<-ctx.Done()
		return nil, nil, nil, nil, ctx.Err()
	}
	return nil, nil, nil, nil, errors.New("refused")
}

func (l *hLegs) reset() []bool {
	l.access.Lock()
	defer l.access.Unlock()
	calls := l.calls
	l.calls = nil
	return calls
}

func hAutoTunnel(t *testing.T, legs *hLegs) *Tunnel {
	t.Helper()
	original, delay := connectTunnel, autoFallbackDelay
	connectTunnel, autoFallbackDelay = legs.connect, 100*time.Millisecond
	t.Cleanup(func() { connectTunnel, autoFallbackDelay = original, delay })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &Tunnel{
		ctx:      ctx,
		logger:   log.NewNOPFactory().NewLogger("masque"),
		options:  TunnelOptions{Mode: ModeAuto, Endpoint: &net.UDPAddr{Port: 443}, H2Endpoint: &net.TCPAddr{Port: 443}},
		failures: make(map[bool]int),
	}
}

// HTTP/3 that stays silent gives way to HTTP/2 after the delay; HTTP/2 is then remembered.
func TestH_AutoFallsBackFromSilentHTTP3(t *testing.T) {
	legs := &hLegs{behavior: map[bool]string{false: "stall", true: "ok"}}
	tunnel := hAutoTunnel(t, legs)
	start := time.Now()
	conn, err := tunnel.connect()
	require.NoError(t, err)
	require.True(t, conn.http2)
	require.GreaterOrEqual(t, time.Since(start), autoFallbackDelay)
	require.Equal(t, []bool{false, true}, legs.reset())
	require.True(t, tunnel.rememberedHTTP2())

	// remembered: the next connect goes straight to HTTP/2
	_, err = tunnel.connect()
	require.NoError(t, err)
	require.Equal(t, []bool{true}, legs.reset())
}

// A fast HTTP/3 error starts HTTP/2 at once.
func TestH_AutoFallsBackFromFailedHTTP3(t *testing.T) {
	legs := &hLegs{behavior: map[bool]string{false: "fail", true: "ok"}}
	tunnel := hAutoTunnel(t, legs)
	start := time.Now()
	conn, err := tunnel.connect()
	require.NoError(t, err)
	require.True(t, conn.http2)
	require.Less(t, time.Since(start), autoFallbackDelay)
}

// An HTTP/3 win clears the HTTP/2 memory; the HTTP/2 window grows with each HTTP/2 win in a row.
func TestH_AutoMemory(t *testing.T) {
	legs := &hLegs{behavior: map[bool]string{false: "fail", true: "ok"}}
	tunnel := hAutoTunnel(t, legs)
	_, err := tunnel.connect()
	require.NoError(t, err)
	require.Equal(t, 1, tunnel.http2Step)
	firstUntil := tunnel.http2Until

	// the window passed: HTTP/3 is tried again, fails, HTTP/2 wins a longer window
	tunnel.http2Until = time.Now().Add(-time.Second)
	legs.reset()
	_, err = tunnel.connect()
	require.NoError(t, err)
	require.Equal(t, []bool{false, true}, legs.reset())
	require.Equal(t, 2, tunnel.http2Step)
	require.Greater(t, tunnel.http2Until.Sub(time.Now()), firstUntil.Sub(time.Now()))

	// HTTP/3 works again after the window: memory cleared
	tunnel.http2Until = time.Now().Add(-time.Second)
	legs.set(false, "ok")
	conn, err := tunnel.connect()
	require.NoError(t, err)
	require.False(t, conn.http2)
	require.Equal(t, 0, tunnel.http2Step)
	require.False(t, tunnel.rememberedHTTP2())
}

// A remembered HTTP/2 that fails is forgotten, and HTTP/3 is tried in the same connect.
func TestH_AutoRememberedHTTP2Fails(t *testing.T) {
	legs := &hLegs{behavior: map[bool]string{false: "fail", true: "ok"}}
	tunnel := hAutoTunnel(t, legs)
	_, err := tunnel.connect()
	require.NoError(t, err)
	legs.reset()
	legs.set(true, "fail")
	legs.set(false, "ok")
	conn, err := tunnel.connect()
	require.NoError(t, err)
	require.False(t, conn.http2)
	require.Equal(t, []bool{true, false}, legs.reset())
}

// Both versions failing report both errors.
func TestH_AutoBothFail(t *testing.T) {
	legs := &hLegs{behavior: map[bool]string{false: "fail", true: "fail"}}
	tunnel := hAutoTunnel(t, legs)
	_, err := tunnel.connect()
	require.Error(t, err)
}

// After failoverAfter failures in a row the tunnel asks for another endpoint, and reports
// successes to the scores.
func TestH_TunnelFailover(t *testing.T) {
	legs := &hLegs{behavior: map[bool]string{false: "fail", true: "fail"}}
	tunnel := hAutoTunnel(t, legs)
	tunnel.options.Mode = ModeHTTP3
	replacement := &net.UDPAddr{IP: net.IPv4(162, 159, 198, 2), Port: 8443}
	var asked []net.Addr
	var connected []net.Addr
	tunnel.SetFailover(func(endpoint net.Addr, http2 bool, elapsed time.Duration) {
		connected = append(connected, endpoint)
	}, func(failed net.Addr, http2 bool) net.Addr {
		asked = append(asked, failed)
		return replacement
	})
	for range failoverAfter {
		_, err := tunnel.connect()
		require.Error(t, err)
	}
	require.Len(t, asked, 1)
	require.Equal(t, replacement, tunnel.options.Endpoint)
	legs.set(false, "ok")
	_, err := tunnel.connect()
	require.NoError(t, err)
	require.Equal(t, []net.Addr{replacement}, connected)
}

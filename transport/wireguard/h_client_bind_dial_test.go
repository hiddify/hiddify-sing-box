package wireguard

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/hiddify/peerfallback"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// hWithin fails when action has not returned in time.
func hWithin(t *testing.T, what string, action func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		action()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal(what, " waits for the detour")
	}
}

func hStalledEndpoint(t *testing.T, ctx context.Context, dialer interface {
	DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
	ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error)
}, fallback ...netip.AddrPort,
) *Endpoint {
	t.Helper()
	ep, err := NewEndpoint(EndpointOptions{
		Context:      ctx,
		Logger:       logger.NOP(),
		Dialer:       dialer,
		MTU:          1280,
		Address:      []netip.Prefix{netip.MustParsePrefix("10.67.0.2/32")},
		PrivateKey:   hKey(t).String(),
		PeerFallback: fallback,
		Peers: []PeerOptions{{
			Endpoint:                    M.ParseSocksaddr("127.0.0.1:9"),
			PublicKey:                   hKey(t).PublicKey().String(),
			AllowedIPs:                  []netip.Prefix{netip.MustParsePrefix("10.67.0.0/24")},
			PersistentKeepaliveInterval: 1,
		}},
	})
	require.NoError(t, err)
	require.NoError(t, ep.Initialize(nil))
	return ep
}

// A detour whose stream stalled holds one packet and nothing else: the endpoint starts, answers
// a status read, connects its bind again and closes. The write ran with the device's locks held.
func TestH_StalledSendDoesNotHoldTheEndpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(pause.WithDefaultManager(service.ContextWithDefaultRegistry(context.Background())))
	defer cancel()
	stalled := &hStalledConn{closed: make(chan struct{}), writing: make(chan struct{}, 1)}
	defer stalled.Close()
	ep := hStalledEndpoint(t, ctx, &hStalledDialer{conn: stalled})
	hWithin(t, "the start", func() {
		require.NoError(t, ep.Start(false))
		require.NoError(t, ep.Start(true))
	})
	select {
	case <-stalled.writing: // the keepalive's handshake is in the detour, which does not take it
	case <-time.After(5 * time.Second):
		t.Fatal("no handshake was sent")
	}
	hWithin(t, "a status read", func() {
		_, err := ep.IpcGet()
		require.NoError(t, err)
	})
	hWithin(t, "connecting the bind again", func() { ep.BindUpdate() })
	hWithin(t, "the close", func() { ep.Close() })
}

// hSilentDialer is a detour that answers neither a dial nor its cancel.
type hSilentDialer struct {
	hLoopbackDialer
	dials   atomic.Int32
	release chan struct{}
}

func (d *hSilentDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dials.Add(1)
	<-d.release
	return nil, net.ErrClosed
}

func (d *hSilentDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	d.dials.Add(1)
	<-d.release
	return nil, net.ErrClosed
}

// A detour that does not answer the dial, nor its cancel, does not keep the bind from closing:
// the dial ran under the lock Close takes. Those who wait for the connection are let go, and
// only one dial is on its way however many wait.
func TestH_ClientBindCloseDuringASilentDial(t *testing.T) {
	dialer := &hSilentDialer{release: make(chan struct{})}
	defer close(dialer.release)
	bind := NewClientBind(context.Background(), logger.NOP(), dialer, true, netip.MustParseAddrPort("127.0.0.1:51820"), [3]uint8{})
	_, _, err := bind.Open(0)
	require.NoError(t, err)
	results := make(chan error, 4)
	for range 4 {
		go func() {
			_, connectErr := bind.connect()
			results <- connectErr
		}()
	}
	require.Eventually(t, func() bool { return dialer.dials.Load() == 1 }, 3*time.Second, 5*time.Millisecond)
	hWithin(t, "the close", func() { bind.Close() })
	for range 4 {
		select {
		case err = <-results:
			require.ErrorIs(t, err, net.ErrClosed)
		case <-time.After(3 * time.Second):
			t.Fatal("a sender still waits for the dial of a closed bind")
		}
	}
	require.EqualValues(t, 1, dialer.dials.Load(), "one dial for all who waited")
}

// An aborted bind stays closed: the endpoint closes with it, and a reconnect that was on its
// way must not open it again behind the close.
func TestH_ClientBindAbortIsForGood(t *testing.T) {
	bind := NewClientBind(context.Background(), logger.NOP(), &hLoopbackDialer{}, false, netip.AddrPort{}, [3]uint8{})
	_, _, err := bind.Open(0)
	require.NoError(t, err)
	require.NoError(t, bind.Close())
	_, _, err = bind.Open(0)
	require.NoError(t, err, "a closed bind opens again")
	bind.hAbort()
	_, _, err = bind.Open(0)
	require.ErrorIs(t, err, net.ErrClosed)
	_, err = bind.connect()
	require.ErrorIs(t, err, net.ErrClosed)
}

// With a fallback address: the fallback moves while the detour is stalled, and the endpoint
// still closes.
func TestH_EndpointCloseWithStalledDetourAndFallback(t *testing.T) {
	wait, interval := peerfallback.Wait, peerfallback.Interval
	peerfallback.Wait, peerfallback.Interval = 300*time.Millisecond, 50*time.Millisecond
	defer func() { peerfallback.Wait, peerfallback.Interval = wait, interval }()
	ctx, cancel := context.WithCancel(pause.WithDefaultManager(service.ContextWithDefaultRegistry(context.Background())))
	defer cancel()
	stalled := &hStalledConn{closed: make(chan struct{}), writing: make(chan struct{}, 1)}
	defer stalled.Close()
	ep := hStalledEndpoint(t, ctx, &hStalledDialer{conn: stalled}, netip.MustParseAddrPort("127.0.0.2:9"))
	hWithin(t, "the start", func() {
		require.NoError(t, ep.Start(false))
		require.NoError(t, ep.Start(true))
	})
	select {
	case <-stalled.writing:
	case <-time.After(5 * time.Second):
		t.Fatal("no handshake was sent")
	}
	time.Sleep(time.Second) // several checks of the fallback, with a handshake that got no answer
	hWithin(t, "the close", func() { ep.Close() })
}

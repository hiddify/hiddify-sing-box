package wireguard

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// hStalledConn is a detour whose stream stalled: a write blocks until the connection closes.
type hStalledConn struct {
	net.PacketConn
	closeOnce sync.Once
	closed    chan struct{}
	writing   chan struct{}
}

func (c *hStalledConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case c.writing <- struct{}{}:
	default:
	}
	<-c.closed
	return 0, net.ErrClosed
}

func (c *hStalledConn) ReadFrom(p []byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}

func (c *hStalledConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

type hStalledDialer struct {
	hLoopbackDialer
	conn *hStalledConn
}

// hStalledStream is the same detour, connected to the peer.
type hStalledStream struct {
	net.Conn
	stalled *hStalledConn
}

func (c *hStalledStream) Write(p []byte) (int, error) { return c.stalled.WriteTo(p, nil) }
func (c *hStalledStream) Read(p []byte) (int, error) {
	<-c.stalled.closed
	return 0, net.ErrClosed
}
func (c *hStalledStream) Close() error                       { return c.stalled.Close() }
func (c *hStalledStream) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *hStalledStream) RemoteAddr() net.Addr               { return &net.UDPAddr{} }
func (c *hStalledStream) SetDeadline(t time.Time) error      { return nil }
func (c *hStalledStream) SetReadDeadline(t time.Time) error  { return nil }
func (c *hStalledStream) SetWriteDeadline(t time.Time) error { return nil }

func (d *hStalledDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return &hStalledStream{stalled: d.conn}, nil
}

func (d *hStalledDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.conn, nil
}

// A send stuck on a stalled detour held the device's network lock, and Close, which needs it to
// close the bind, waited for good: the box could not stop.
func TestH_EndpointCloseWithStalledDetour(t *testing.T) {
	ctx, cancel := context.WithCancel(pause.WithDefaultManager(service.ContextWithDefaultRegistry(context.Background())))
	defer cancel()
	stalled := &hStalledConn{closed: make(chan struct{}), writing: make(chan struct{}, 1)}
	defer stalled.Close()
	ep, err := NewEndpoint(EndpointOptions{
		Context:    ctx,
		Logger:     logger.NOP(),
		Dialer:     &hStalledDialer{conn: stalled},
		MTU:        1280,
		Address:    []netip.Prefix{netip.MustParsePrefix("10.67.0.2/32")},
		PrivateKey: hKey(t).String(),
		Peers: []PeerOptions{{
			Endpoint:                    M.ParseSocksaddr("127.0.0.1:9"),
			PublicKey:                   hKey(t).PublicKey().String(),
			AllowedIPs:                  []netip.Prefix{netip.MustParsePrefix("10.67.0.0/24")},
			PersistentKeepaliveInterval: 1,
		}},
	})
	require.NoError(t, err)
	require.NoError(t, ep.Initialize(nil))
	go func() {
		if ep.Start(false) == nil {
			ep.Start(true)
		}
	}()
	select {
	case <-stalled.writing:
	case <-time.After(5 * time.Second):
		t.Fatal("no handshake was sent")
	}

	closed := make(chan struct{})
	go func() {
		ep.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close waits for a send stuck on the detour")
	}
}

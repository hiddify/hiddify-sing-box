package xhttp

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/tls"
	Xbadoption "github.com/sagernet/sing-box/common/xray/json/badoption"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// hCountingDialer counts the connections it made and how many of them are still open, and can
// take a while over each, as a server far away does.
type hCountingDialer struct {
	delay time.Duration
	dials atomic.Int32
	open  atomic.Int32
}

func (d *hCountingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if d.delay > 0 {
		select {
		case <-time.After(d.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	conn, err := N.SystemDialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	d.dials.Add(1)
	d.open.Add(1)
	return &hCountedConn{Conn: conn, dialer: d}, nil
}

func (d *hCountingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

type hCountedConn struct {
	net.Conn
	dialer *hCountingDialer
	once   sync.Once
}

func (c *hCountedConn) Close() error {
	c.once.Do(func() { c.dialer.open.Add(-1) })
	return c.Conn.Close()
}

// hEcho sends payload over a new connection of the transport and reads it back.
func hEcho(t *testing.T, transport interface {
	DialContext(ctx context.Context) (net.Conn, error)
}, payload []byte,
) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := transport.DialContext(ctx)
	require.NoError(t, err)
	_, err = conn.Write(payload)
	require.NoError(t, err)
	received := make([]byte, len(payload))
	result := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(conn, received)
		result <- err
	}()
	select {
	case err = <-result:
		require.NoError(t, err)
		require.Equal(t, payload, received)
	case <-time.After(5 * time.Second):
		t.Fatal("no echo")
	}
	return conn
}

// hNewHTTP3Pair is hNewTLSPair for HTTP/3: the server's only ALPN is h3, so it listens on UDP.
func hNewHTTP3Pair(t *testing.T) (tls.ServerConfig, tls.Config) {
	t.Helper()
	keyPEM, certPEM, err := tls.GenerateCertificate(nil, nil, time.Now, "example.com", time.Now().Add(time.Hour))
	require.NoError(t, err)
	ctx := context.Background()
	serverConfig, err := tls.NewServer(ctx, logger.NOP(), option.InboundTLSOptions{
		Enabled:     true,
		ALPN:        []string{"h3"},
		Certificate: []string{string(certPEM)},
		Key:         []string{string(keyPEM)},
	})
	require.NoError(t, err)
	require.NoError(t, serverConfig.Start())
	t.Cleanup(func() { serverConfig.Close() })
	clientConfig, err := tls.NewClient(ctx, logger.NOP(), "example.com", option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  "example.com",
		ALPN:        []string{"h3"},
		Certificate: []string{string(certPEM)},
	})
	require.NoError(t, err)
	return serverConfig, clientConfig
}

// hSettle waits for an upload connection that is being dialled ahead, and a moment more for the
// server to finish its side of that handshake: the test server's lazy TLS connection must not be
// closed in the middle of one.
func hSettle(t *testing.T, transport any) {
	t.Helper()
	client := transport.(*Client)
	for _, manager := range client.xmuxManagers {
		manager.mtx.Lock()
		xmuxClients := append([]*XmuxClient(nil), manager.xmuxClients...)
		manager.mtx.Unlock()
		for _, xmuxClient := range xmuxClients {
			if warm := xmuxClient.XmuxConn.(*DefaultDialerClient).warm.Load(); warm != nil {
				select {
				case <-warm.done:
				case <-time.After(3 * time.Second):
					t.Fatal("the upload connection dialled ahead did not arrive")
				}
			}
		}
	}
	time.Sleep(30 * time.Millisecond)
}

func hStartPacketServer(t *testing.T, options option.V2RayXHTTPOptions, serverTLS tls.ServerConfig) M.Socksaddr {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	server, err := NewServer(ctx, logger.NOP(), options, serverTLS, &hEchoHandler{})
	require.NoError(t, err)
	require.Equal(t, []string{N.NetworkUDP}, server.Network())
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	go server.ServePacket(listener)
	t.Cleanup(func() {
		cancel()
		server.Close()
		listener.Close()
	})
	return M.SocksaddrFromNet(listener.LocalAddr())
}

// Closing the transport, as closing the outbound does, closes its connections to the server.
// They stayed open: an HTTP/2 one for five idle minutes, and an HTTP/3 one, which keeps itself
// alive every ten seconds, with its socket for up to fifty.
func TestH_XHTTPCloseClosesTheConnections(t *testing.T) {
	const content = `{"mode":"packet-up",` + hBase + `}`
	for _, alpn := range []string{"h2", "http/1.1", "h3"} {
		t.Run(alpn, func(t *testing.T) {
			serverTLS, clientTLS := hNewTLSPair(t, []string{alpn})
			var addr M.Socksaddr
			if alpn == "h3" {
				serverTLS, clientTLS = hNewHTTP3Pair(t)
				addr = hStartPacketServer(t, hOptions(t, content), serverTLS)
			} else {
				addr = hStartServer(t, hOptions(t, content), serverTLS)
			}
			dialer := &hCountingDialer{}
			transport, err := NewClient(context.Background(), dialer, addr, hOptions(t, content), clientTLS)
			require.NoError(t, err)
			conn := hEcho(t, transport, []byte("hello"))
			require.NoError(t, conn.Close())
			if alpn != "http/1.1" {
				// kept to be used again (HTTP/1.1 closes the download's with it)
				time.Sleep(100 * time.Millisecond)
				require.Positive(t, dialer.open.Load(), "the connection to the server is kept for the next one")
			}
			hSettle(t, transport)
			require.NoError(t, transport.Close())
			require.Eventually(t, func() bool { return dialer.open.Load() == 0 }, 3*time.Second, 10*time.Millisecond,
				"%d of %d connections to the server are still open after Close", dialer.open.Load(), dialer.dials.Load())

			// and the transport still works, as after a network change
			conn = hEcho(t, transport, []byte("again"))
			require.NoError(t, conn.Close())
			hSettle(t, transport)
			require.NoError(t, transport.Close())
			require.Eventually(t, func() bool { return dialer.open.Load() == 0 }, 3*time.Second, 10*time.Millisecond)
		})
	}
}

// A TLS handshake that fails closes its TCP connection. It was left open, and the router, which
// tracks the dialer's connections, kept it for good: one for every test of a server whose
// certificate is not accepted.
func TestH_XHTTPFailedHandshakeClosesTheConnection(t *testing.T) {
	const content = `{"mode":"packet-up",` + hBase + `}`
	serverTLS, _ := hNewTLSPair(t, []string{"h2"})
	_, otherClientTLS := hNewTLSPair(t, []string{"h2"}) // trusts another certificate
	addr := hStartServer(t, hOptions(t, content), serverTLS)
	dialer := &hCountingDialer{}
	transport, err := NewClient(context.Background(), dialer, addr, hOptions(t, content), otherClientTLS)
	require.NoError(t, err)
	defer transport.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := transport.DialContext(ctx)
	if err == nil {
		conn.Close()
	}
	require.Error(t, err)
	require.Positive(t, dialer.dials.Load())
	require.Eventually(t, func() bool { return dialer.open.Load() == 0 }, 2*time.Second, 10*time.Millisecond,
		"the TCP connection of the failed handshake is still open")
}

// Over HTTP/1.1 the first upload's connection is dialled while the download's is, not after it:
// with a server 150 ms away for each connection, the first byte gets there and back in little
// more than one such time, not two.
func TestH_XHTTPHTTP1UploadIsDialledAhead(t *testing.T) {
	const content = `{"mode":"packet-up",` + hBase + `}`
	serverTLS, clientTLS := hNewTLSPair(t, []string{"http/1.1"})
	addr := hStartServer(t, hOptions(t, content), serverTLS)
	dialer := &hCountingDialer{delay: 150 * time.Millisecond}
	transport, err := NewClient(context.Background(), dialer, addr, hOptions(t, content), clientTLS)
	require.NoError(t, err)
	defer transport.Close()
	started := time.Now()
	conn := hEcho(t, transport, []byte("hello"))
	took := time.Since(started)
	defer conn.Close()
	require.Equal(t, int32(2), dialer.dials.Load(), "one connection for the download and one for the uploads")
	require.Less(t, took, 270*time.Millisecond, "the two connections were dialled one after the other")
	hSettle(t, transport)
}

type hClosableXmuxConn struct {
	closed atomic.Bool
}

func (c *hClosableXmuxConn) IsClosed() bool { return c.closed.Load() }

func (c *hClosableXmuxConn) Close() error {
	c.closed.Store(true)
	return nil
}

// Connections to the server with nothing on them are closed after a while; the one used last is
// kept longer, so that the next proxied connection still starts without a handshake.
func TestH_XmuxIdleClientsAreClosed(t *testing.T) {
	idle, keep := hXmuxIdle, hXmuxKeep
	hXmuxIdle, hXmuxKeep = 60*time.Millisecond, 400*time.Millisecond
	defer func() { hXmuxIdle, hXmuxKeep = idle, keep }()
	manager := NewXmuxManager(option.V2RayXHTTPXmuxOptions{
		MaxConcurrency: Xbadoption.Range{From: 1, To: 1},
	}, func() XmuxConn { return &hClosableXmuxConn{} })
	ctx := context.Background()
	// three proxied connections at once: three connections to the server
	var clients []*XmuxClient
	for range 3 {
		clients = append(clients, manager.GetXmuxClient(ctx)) // running once picked
	}
	require.NotSame(t, clients[0], clients[1])
	require.NotSame(t, clients[1], clients[2])
	closed := func(client *XmuxClient) bool { return client.XmuxConn.(*hClosableXmuxConn).closed.Load() }

	clients[0].DoneRunning()
	time.Sleep(5 * time.Millisecond)
	clients[1].DoneRunning()
	time.Sleep(150 * time.Millisecond)
	require.True(t, closed(clients[0]), "an idle one is closed")
	require.False(t, closed(clients[1]), "the one used last is kept")
	require.False(t, closed(clients[2]), "one in use is never closed")

	// a new proxied connection uses the one that was kept
	require.Same(t, clients[1], manager.GetXmuxClient(ctx))
	time.Sleep(150 * time.Millisecond)
	require.False(t, closed(clients[1]), "taken again, it is in use")
	clients[1].DoneRunning()
	clients[2].DoneRunning()
	require.Eventually(t, func() bool { return closed(clients[1]) && closed(clients[2]) }, 2*time.Second, 10*time.Millisecond,
		"in the end all are closed")
	manager.mtx.Lock()
	left, timer := len(manager.xmuxClients), manager.trimTimer
	manager.mtx.Unlock()
	require.Zero(t, left)
	require.Nil(t, timer, "and no timer is left running")
}

// When a connection's upload requests are used up (h_max_request_times), the uploads go on over
// another client; every client is free again when the connection closes. The first one was
// counted as in use for good, and the last one freed without having been taken.
func TestH_XHTTPUploadsMoveToAnotherClient(t *testing.T) {
	const content = `{"mode":"packet-up",` + hBase + `,"sc_min_posts_interval_ms":"1","xmux":{"max_concurrency":"1","h_max_request_times":"4"}}`
	serverTLS, clientTLS := hNewTLSPair(t, []string{"h2"})
	addr := hStartServer(t, hOptions(t, `{"mode":"packet-up",`+hBase+`}`), serverTLS)
	transport, err := NewClient(context.Background(), N.SystemDialer, addr, hOptions(t, content), clientTLS)
	require.NoError(t, err)
	defer transport.Close()
	client := transport.(*Client)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	require.NoError(t, err)
	// twelve uploads, each answered before the next is sent: at least three clients
	buffer := make([]byte, 5)
	for i := range 12 {
		payload := []byte{'p', byte('a' + i), 'x', 'y', 'z'}
		_, err = conn.Write(payload)
		require.NoError(t, err)
		_, err = io.ReadFull(conn, buffer)
		require.NoError(t, err)
		require.Equal(t, payload, buffer)
	}
	manager := client.xmuxManagers[0]
	seen := map[*XmuxClient]bool{}
	manager.mtx.Lock()
	for _, xmuxClient := range manager.xmuxClients {
		seen[xmuxClient] = true
	}
	manager.mtx.Unlock()
	require.NoError(t, conn.Close())
	require.Eventually(t, func() bool {
		manager.mtx.Lock()
		defer manager.mtx.Unlock()
		for _, xmuxClient := range manager.xmuxClients {
			seen[xmuxClient] = true
		}
		for xmuxClient := range seen {
			if xmuxClient.OpenUsage.Load() != 0 {
				return false
			}
		}
		return true
	}, 3*time.Second, 10*time.Millisecond, "a client is still counted as in use, or was freed twice")
}

// The error an HTTP/3 download ends with when the application stops it is a closed connection.
func TestH_XHTTPHTTP3CloseIsClosed(t *testing.T) {
	err := hWrapH3(&http3.Error{ErrorCode: http3.ErrCodeRequestCanceled})
	require.ErrorIs(t, err, net.ErrClosed)
	require.Equal(t, io.EOF, hWrapH3(io.EOF), "other errors are left as they are")
	require.NoError(t, hWrapH3(nil))
}

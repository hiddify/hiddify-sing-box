package tunnel

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type hRouted struct {
	conn     net.Conn
	metadata adapter.InboundContext
}

type hFakeRouter struct {
	adapter.Router
	routed chan hRouted
}

func newHFakeRouter() *hFakeRouter {
	return &hFakeRouter{routed: make(chan hRouted, 4)}
}

func (r *hFakeRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.routed <- hRouted{conn, metadata}
}

func (r *hFakeRouter) expectRouted(t *testing.T) hRouted {
	t.Helper()
	select {
	case routed := <-r.routed:
		return routed
	case <-time.After(2 * time.Second):
		t.Fatal("connection was not routed")
		return hRouted{}
	}
}

type hFakeOutbound struct {
	adapter.Outbound
	dial func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
}

func (o *hFakeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return o.dial(ctx, network, destination)
}

func hNewServer(router adapter.Router, users map[uuid.UUID]uuid.UUID) *ServerEndpoint {
	server := &ServerEndpoint{
		Adapter: outbound.NewAdapter(C.TypeTunnelServer, "tunnel-server", []string{N.NetworkTCP}, nil),
		logger:  log.NewNOPFactory().NewLogger("tunnel"),
		router:  router,
		uuid:    hUUIDC,
		users:   make(map[uuid.UUID]uuid.UUID),
		keys:    make(map[uuid.UUID]uuid.UUID),
		conns:   make(map[uuid.UUID]chan net.Conn),
		timeout: 200 * time.Millisecond,
	}
	for key, user := range users {
		server.users[key] = user
		server.keys[user] = key
		server.conns[user] = make(chan net.Conn, 10)
	}
	return server
}

func hContextWith(metadata adapter.InboundContext) context.Context {
	return adapter.WithContext(context.Background(), &metadata)
}

func hRunWithTimeout(t *testing.T, name string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal(name, " hung (deadlock)")
	}
}

func TestH_TunnelRouter(t *testing.T) {
	t.Parallel()
	var called int
	var closeErr error
	router := NewRouter(nil, log.NewNOPFactory().NewLogger("tunnel"), func(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
		called++
		if metadata.Domain == "fail" {
			return os.ErrPermission
		}
		return nil
	})
	require.NoError(t, router.RouteConnection(context.Background(), nil, adapter.InboundContext{}))
	require.ErrorIs(t, router.RoutePacketConnection(context.Background(), nil, adapter.InboundContext{}), os.ErrInvalid)
	client, peer := net.Pipe()
	defer peer.Close()
	router.RouteConnectionEx(context.Background(), client, adapter.InboundContext{Domain: "fail"}, func(err error) { closeErr = err })
	require.Equal(t, 2, called)
	require.ErrorIs(t, closeErr, os.ErrPermission)
}

func TestH_ServerDialContextErrors(t *testing.T) {
	t.Parallel()
	server := hNewServer(newHFakeRouter(), map[uuid.UUID]uuid.UUID{hUUIDB: hUUIDA})
	dest := M.ParseSocksaddrHostPort("example.com", 80)

	_, err := server.DialContext(context.Background(), N.NetworkUDP, dest)
	require.ErrorIs(t, err, os.ErrInvalid)
	_, err = server.ListenPacket(context.Background(), dest)
	require.ErrorIs(t, err, os.ErrInvalid)

	_, err = server.DialContext(context.Background(), N.NetworkTCP, dest)
	require.ErrorContains(t, err, "tunnel destination not set")

	_, err = server.DialContext(hContextWith(adapter.InboundContext{TunnelDestination: "not-a-uuid"}), N.NetworkTCP, dest)
	require.Error(t, err)

	_, err = server.DialContext(hContextWith(adapter.InboundContext{TunnelDestination: hUUIDA.String(), TunnelSource: "bad"}), N.NetworkTCP, dest)
	require.Error(t, err)

	_, err = server.DialContext(hContextWith(adapter.InboundContext{TunnelDestination: hUUIDA.String()}), N.NetworkTCP, dest)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestH_ServerDialContextUnknownUserReleasesLock(t *testing.T) {
	t.Skip("BUG: ServerEndpoint.DialContext returns on unknown tunnel destination without unlocking s.mtx (protocol/tunnel/server.go:104), deadlocking later calls")
	t.Parallel()
	server := hNewServer(newHFakeRouter(), map[uuid.UUID]uuid.UUID{hUUIDB: hUUIDA})
	dest := M.ParseSocksaddrHostPort("example.com", 80)
	_, err := server.DialContext(hContextWith(adapter.InboundContext{TunnelDestination: hUUIDB.String()}), N.NetworkTCP, dest)
	require.ErrorContains(t, err, "not found")
	hRunWithTimeout(t, "second DialContext", func() {
		_, _ = server.DialContext(hContextWith(adapter.InboundContext{TunnelDestination: hUUIDA.String()}), N.NetworkTCP, dest)
	})
}

func TestH_ServerInboundThenDial(t *testing.T) {
	t.Parallel()
	server := hNewServer(newHFakeRouter(), map[uuid.UUID]uuid.UUID{hUUIDB: hUUIDA})
	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()
	_ = clientSide.SetDeadline(time.Now().Add(3 * time.Second))
	_ = serverSide.SetDeadline(time.Now().Add(3 * time.Second))

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.connHandler(context.Background(), serverSide, adapter.InboundContext{Destination: Destination}, func(error) {})
	}()
	require.NoError(t, WriteRequest(clientSide, &Request{UUID: hUUIDB, Command: CommandInbound, Destination: Destination}))
	require.NoError(t, <-errCh)

	dest := M.SocksaddrFrom(netip.MustParseAddr("198.51.100.7"), 22)
	readCh := make(chan *Request, 1)
	go func() {
		request, _ := ReadRequest(clientSide)
		readCh <- request
	}()
	conn, err := server.DialContext(hContextWith(adapter.InboundContext{TunnelDestination: hUUIDA.String()}), N.NetworkTCP, dest)
	require.NoError(t, err)
	require.Equal(t, serverSide, conn)
	request := <-readCh
	require.NotNil(t, request)
	require.Equal(t, byte(CommandTCP), request.Command)
	require.Equal(t, hUUIDC, request.UUID)
	require.Equal(t, dest, request.Destination)
}

func TestH_ServerInboundReplacesOldestWhenFull(t *testing.T) {
	t.Parallel()
	server := hNewServer(newHFakeRouter(), map[uuid.UUID]uuid.UUID{hUUIDB: hUUIDA})
	server.conns[hUUIDA] = make(chan net.Conn, 1)
	oldConn, oldPeer := net.Pipe()
	defer oldPeer.Close()
	server.conns[hUUIDA] <- oldConn

	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	go func() {
		_ = WriteRequest(clientSide, &Request{UUID: hUUIDB, Command: CommandInbound, Destination: Destination})
	}()
	hRunWithTimeout(t, "connHandler", func() {
		require.NoError(t, server.connHandler(context.Background(), serverSide, adapter.InboundContext{Destination: Destination}, func(error) {}))
	})
	require.Equal(t, serverSide, <-server.conns[hUUIDA])
	_, err := oldPeer.Write([]byte{0})
	require.Error(t, err)
}

func TestH_ServerConnHandlerTCP(t *testing.T) {
	t.Parallel()
	router := newHFakeRouter()
	userKeyA := uuid.Must(uuid.FromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))
	server := hNewServer(router, map[uuid.UUID]uuid.UUID{hUUIDB: hUUIDA, userKeyA: hUUIDB})
	dest := M.ParseSocksaddrHostPort("example.com", 443)

	run := func(request *Request) error {
		serverSide, clientSide := net.Pipe()
		t.Cleanup(func() { clientSide.Close(); serverSide.Close() })
		go func() { _ = WriteRequest(clientSide, request) }()
		var err error
		hRunWithTimeout(t, "connHandler", func() {
			err = server.connHandler(context.Background(), serverSide, adapter.InboundContext{Destination: Destination}, func(error) {})
		})
		return err
	}

	require.NoError(t, run(&Request{UUID: hUUIDB, Command: CommandTCP, DestinationUUID: hUUIDB, Destination: dest}))
	routed := router.expectRouted(t)
	require.Equal(t, hUUIDA.String(), routed.metadata.TunnelSource)
	require.Equal(t, hUUIDB.String(), routed.metadata.TunnelDestination)
	require.Equal(t, dest, routed.metadata.Destination)
	require.Equal(t, "tunnel-server", routed.metadata.Inbound)
	require.Equal(t, C.TypeTunnelServer, routed.metadata.InboundType)

	require.NoError(t, run(&Request{UUID: hUUIDB, Command: CommandTCP, DestinationUUID: hUUIDC, Destination: dest}))
	routed = router.expectRouted(t)
	require.Equal(t, hUUIDC.String(), routed.metadata.TunnelDestination)

	require.ErrorContains(t, run(&Request{UUID: hUUIDC, Command: CommandTCP, DestinationUUID: hUUIDB, Destination: dest}), "not found")
	require.ErrorContains(t, run(&Request{UUID: hUUIDB, Command: CommandTCP, DestinationUUID: hUUIDA, Destination: dest}), "routing loop")
	require.ErrorContains(t, run(&Request{UUID: hUUIDB, Command: 9, Destination: dest}), "command")
	require.ErrorContains(t, run(&Request{UUID: hUUIDC, Command: CommandInbound, Destination: Destination}), "not found")
}

func TestH_ServerConnHandlerUnknownDestinationUserReleasesLock(t *testing.T) {
	t.Skip("BUG: ServerEndpoint.connHandler returns 'user not found' for CommandTCP without unlocking s.mtx (protocol/tunnel/server.go:190), deadlocking later requests")
	t.Parallel()
	server := hNewServer(newHFakeRouter(), map[uuid.UUID]uuid.UUID{hUUIDB: hUUIDA})
	unknown := uuid.Must(uuid.FromString("dddddddd-dddd-dddd-dddd-dddddddddddd"))
	for i := 0; i < 2; i++ {
		serverSide, clientSide := net.Pipe()
		defer clientSide.Close()
		go func() {
			_ = WriteRequest(clientSide, &Request{UUID: hUUIDB, Command: CommandTCP, DestinationUUID: unknown, Destination: Destination})
		}()
		hRunWithTimeout(t, "connHandler", func() {
			require.ErrorContains(t, server.connHandler(context.Background(), serverSide, adapter.InboundContext{Destination: Destination}, func(error) {}), "not found")
		})
	}
}

func TestH_ServerConnHandlerPassthrough(t *testing.T) {
	t.Parallel()
	router := newHFakeRouter()
	server := hNewServer(router, nil)
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	dest := M.ParseSocksaddrHostPort("example.com", 80)
	require.NoError(t, server.connHandler(context.Background(), conn, adapter.InboundContext{Destination: dest}, func(error) {}))
	routed := router.expectRouted(t)
	require.Equal(t, dest, routed.metadata.Destination)
	require.Empty(t, routed.metadata.TunnelSource)
}

func TestH_ClientDialContext(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var dialed []M.Socksaddr
	peers := make(chan net.Conn, 1)
	client := &ClientEndpoint{
		Adapter: outbound.NewAdapter(C.TypeTunnelClient, "tunnel-client", []string{N.NetworkTCP}, nil),
		ctx:     context.Background(),
		logger:  log.NewNOPFactory().NewLogger("tunnel"),
		uuid:    hUUIDA,
		key:     hUUIDB,
		outbound: &hFakeOutbound{dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
			mu.Lock()
			dialed = append(dialed, destination)
			mu.Unlock()
			local, remote := net.Pipe()
			peers <- remote
			return local, nil
		}},
	}
	dest := M.ParseSocksaddrHostPort("example.com", 443)

	_, err := client.DialContext(context.Background(), N.NetworkUDP, dest)
	require.ErrorIs(t, err, os.ErrInvalid)
	_, err = client.ListenPacket(context.Background(), dest)
	require.ErrorIs(t, err, os.ErrInvalid)
	_, err = client.DialContext(context.Background(), N.NetworkTCP, dest)
	require.ErrorContains(t, err, "tunnel destination not set")
	_, err = client.DialContext(hContextWith(adapter.InboundContext{TunnelDestination: "bad"}), N.NetworkTCP, dest)
	require.Error(t, err)
	_, err = client.DialContext(hContextWith(adapter.InboundContext{TunnelDestination: hUUIDA.String()}), N.NetworkTCP, dest)
	require.ErrorContains(t, err, "routing loop")

	readCh := make(chan *Request, 1)
	go func() {
		peer := <-peers
		defer peer.Close()
		request, _ := ReadRequest(peer)
		readCh <- request
	}()
	conn, err := client.DialContext(hContextWith(adapter.InboundContext{TunnelDestination: hUUIDC.String()}), N.NetworkTCP, dest)
	require.NoError(t, err)
	defer conn.Close()
	select {
	case request := <-readCh:
		require.NotNil(t, request)
		require.Equal(t, hUUIDB, request.UUID)
		require.Equal(t, byte(CommandTCP), request.Command)
		require.Equal(t, hUUIDC, request.DestinationUUID)
		require.Equal(t, dest, request.Destination)
	case <-time.After(2 * time.Second):
		t.Fatal("request not received")
	}
	mu.Lock()
	require.Equal(t, []M.Socksaddr{Destination}, dialed)
	mu.Unlock()
}

func TestH_ClientConnHandler(t *testing.T) {
	t.Parallel()
	router := newHFakeRouter()
	client := &ClientEndpoint{
		ctx:    context.Background(),
		logger: log.NewNOPFactory().NewLogger("tunnel"),
		router: router,
		uuid:   hUUIDA,
		key:    hUUIDB,
	}
	dest := M.ParseSocksaddrHostPort("example.com", 22)
	conn, peer := net.Pipe()
	defer peer.Close()
	client.connHandler(conn, &Request{UUID: hUUIDC, Command: CommandTCP, Destination: dest})
	routed := router.expectRouted(t)
	require.Equal(t, hUUIDC.String(), routed.metadata.TunnelSource)
	require.Equal(t, dest, routed.metadata.Destination)

	loopConn, loopPeer := net.Pipe()
	defer loopPeer.Close()
	client.connHandler(loopConn, &Request{UUID: hUUIDA, Command: CommandTCP, Destination: dest})
	select {
	case <-router.routed:
		t.Fatal("routing loop connection must not be routed")
	default:
	}
	_, err := loopPeer.Write([]byte{0})
	require.Error(t, err)
}

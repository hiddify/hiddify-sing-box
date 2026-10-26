package shadowsocks

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/sagernet/sing-box/adapter/htest"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	obfs "github.com/sagernet/sing-box/transport/simple-obfs"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type testRouter struct {
	adapter.Router
	mu       sync.Mutex
	metadata []adapter.InboundContext
	routed   chan struct{}
}

func newTestRouter() *testRouter {
	return &testRouter{routed: make(chan struct{}, 16)}
}

func (r *testRouter) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	r.mu.Lock()
	r.metadata = append(r.metadata, metadata)
	r.mu.Unlock()
	r.routed <- struct{}{}
	_, err := io.Copy(conn, conn)
	return err
}

func (r *testRouter) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return conn.Close()
}

func (r *testRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	err := r.RouteConnection(ctx, conn, metadata)
	conn.Close()
	if onClose != nil {
		onClose(err)
	}
}

func (r *testRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	conn.Close()
}

func freeTCPPort(t *testing.T) uint16 {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return uint16(port)
}

func TestH_ShadowsocksInboundRejectsUnknownObfsMode(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	cases := map[string]option.ShadowsocksInboundOptions{
		"single": {Method: "aes-128-gcm", Password: "p", ObfsMode: "websocket"},
		"multi":  {Method: "aes-128-gcm", Users: []option.ShadowsocksUser{{Name: "a", Password: "p"}}, ObfsMode: "HTTP"},
		"relay": {
			Method:       "2022-blake3-aes-128-gcm",
			Password:     "AAAAAAAAAAAAAAAAAAAAAA==",
			Destinations: []option.ShadowsocksDestination{{Name: "d", Password: "AAAAAAAAAAAAAAAAAAAAAA==", ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1}}},
			ObfsMode:     "tls1.3",
		},
	}
	for name, options := range cases {
		_, err := NewInbound(context.Background(), newTestRouter(), logger, "ss-in", options)
		require.ErrorContains(t, err, "unsupported obfs mode", name)
	}
	for _, mode := range []string{"", "http", "tls"} {
		for name, options := range cases {
			options.ObfsMode = mode
			in, err := NewInbound(context.Background(), newTestRouter(), logger, "ss-in", options)
			require.NoError(t, err, name+"/"+mode)
			require.NoError(t, htest.Close(in))
		}
	}
}

func startShadowsocksInbound(t *testing.T, options option.ShadowsocksInboundOptions) (*testRouter, uint16) {
	router := newTestRouter()
	port := freeTCPPort(t)
	listen := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	options.ListenOptions = option.ListenOptions{Listen: &listen, ListenPort: port}
	options.Network = "tcp"
	in, err := NewInbound(context.Background(), router, log.NewNOPFactory().Logger(), "ss-in", options)
	require.NoError(t, err)
	require.NoError(t, htest.Start(in, adapter.StartStateStart))
	t.Cleanup(func() { htest.Close(in) })
	return router, port
}

func dialShadowsocks(t *testing.T, port uint16, password, plugin, pluginOpts string, payload string) error {
	out, err := NewOutbound(context.Background(), newTestRouter(), log.NewNOPFactory().Logger(), "ss-out", option.ShadowsocksOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: port},
		Method:        "aes-128-gcm",
		Password:      password,
		Plugin:        plugin,
		PluginOptions: pluginOpts,
		Network:       "tcp",
	})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("203.0.113.9:8443"))
	if err != nil {
		return err
	}
	defer conn.Close()
	watchdog := time.AfterFunc(2*time.Second, func() { conn.Close() })
	defer watchdog.Stop()
	if _, err = conn.Write([]byte(payload)); err != nil {
		return err
	}
	reply := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, reply); err != nil {
		return err
	}
	if string(reply) != payload {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func TestH_ShadowsocksObfsRoundTrip(t *testing.T) {
	t.Parallel()
	plugins := map[string]string{
		"":     "",
		"http": "obfs=http;obfs-host=www.example.com",
		"tls":  "obfs=tls;obfs-host=www.example.com",
	}
	inbounds := map[string]option.ShadowsocksInboundOptions{
		"single": {Method: "aes-128-gcm", Password: "single-pass"},
		"multi":  {Method: "aes-128-gcm", Users: []option.ShadowsocksUser{{Name: "u0", Password: "other"}, {Name: "u1", Password: "single-pass"}}},
	}
	for kind, base := range inbounds {
		for mode, pluginOpts := range plugins {
			options := base
			options.ObfsMode = mode
			router, port := startShadowsocksInbound(t, options)
			plugin := ""
			if pluginOpts != "" {
				plugin = "obfs-local"
			}
			require.NoError(t, dialShadowsocks(t, port, "single-pass", plugin, pluginOpts, "obfs payload "+mode), kind+"/"+mode)
			select {
			case <-router.routed:
			case <-time.After(5 * time.Second):
				t.Fatal("not routed: " + kind + "/" + mode)
			}
			router.mu.Lock()
			md := router.metadata[0]
			router.mu.Unlock()
			require.Equal(t, "ss-in", md.Inbound, kind+"/"+mode)
			require.Equal(t, M.ParseSocksaddr("203.0.113.9:8443"), md.Destination, kind+"/"+mode)
			if kind == "multi" {
				require.Equal(t, "u1", md.User)
			}
		}
	}
}

func TestH_ShadowsocksObfsMismatch(t *testing.T) {
	t.Parallel()
	cases := []struct {
		inboundMode string
		pluginOpts  string
	}{
		{"http", ""},
		{"tls", ""},
		{"", "obfs=http;obfs-host=www.example.com"},
		{"http", "obfs=tls;obfs-host=www.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.inboundMode+"|"+tc.pluginOpts, func(t *testing.T) {
			t.Parallel()
			router, port := startShadowsocksInbound(t, option.ShadowsocksInboundOptions{
				Method: "aes-128-gcm", Password: "pass", ObfsMode: tc.inboundMode,
			})
			plugin := ""
			if tc.pluginOpts != "" {
				plugin = "obfs-local"
			}
			require.Error(t, dialShadowsocks(t, port, "pass", plugin, tc.pluginOpts, "x"))
			select {
			case <-router.routed:
				t.Fatal("mismatched obfs connection was routed")
			default:
			}
		})
	}
}

// fallbackRouter dials connections routed to the fallback address, like a direct
// outbound would, and echoes everything else like testRouter.
type fallbackRouter struct {
	*testRouter
	fallback M.Socksaddr
}

func (r *fallbackRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if metadata.Destination != r.fallback {
		r.testRouter.RouteConnectionEx(ctx, conn, metadata, onClose)
		return
	}
	r.mu.Lock()
	r.metadata = append(r.metadata, metadata)
	r.mu.Unlock()
	r.routed <- struct{}{}
	upstream, err := net.Dial("tcp", metadata.Destination.String())
	if err == nil {
		go io.Copy(upstream, conn)
		_, err = io.Copy(conn, upstream)
		upstream.Close()
	}
	conn.Close()
	if onClose != nil {
		onClose(err)
	}
}

func startDecoy(t *testing.T, useTLS bool) (*httptest.Server, option.ServerOptions) {
	decoy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "decoy site "+r.Host+r.URL.Path)
	}))
	if useTLS {
		decoy.StartTLS()
	} else {
		decoy.Start()
	}
	t.Cleanup(decoy.Close)
	addr := decoy.Listener.Addr().(*net.TCPAddr)
	return decoy, option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(addr.Port)}
}

func startShadowsocksInboundWithRouter(t *testing.T, router adapter.Router, options option.ShadowsocksInboundOptions) uint16 {
	port := freeTCPPort(t)
	listen := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	options.ListenOptions = option.ListenOptions{Listen: &listen, ListenPort: port}
	options.Network = "tcp"
	in, err := NewInbound(context.Background(), router, log.NewNOPFactory().Logger(), "ss-in", options)
	require.NoError(t, err)
	require.NoError(t, htest.Start(in, adapter.StartStateStart))
	t.Cleanup(func() { htest.Close(in) })
	return port
}

func probe(t *testing.T, port uint16, useTLS bool) string {
	client := &http.Client{Timeout: 3 * time.Second}
	scheme := "http"
	if useTLS {
		scheme = "https"
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	response, err := client.Get(fmt.Sprintf("%s://127.0.0.1:%d/probe", scheme, port))
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	return string(body)
}

func TestH_ShadowsocksObfsFallback(t *testing.T) {
	t.Parallel()
	inbounds := map[string]option.ShadowsocksInboundOptions{
		"single": {Method: "aes-128-gcm", Password: "pass"},
		"multi":  {Method: "aes-128-gcm", Users: []option.ShadowsocksUser{{Name: "u", Password: "pass"}}},
		"relay": {
			Method:       "2022-blake3-aes-128-gcm",
			Password:     "AAAAAAAAAAAAAAAAAAAAAA==",
			Destinations: []option.ShadowsocksDestination{{Name: "d", Password: "AAAAAAAAAAAAAAAAAAAAAA==", ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1}}},
		},
	}
	cases := []struct {
		mode     string
		decoyTLS bool
	}{
		{"tls", true},  // a censor's real TLS handshake against a FakeTLS server
		{"tls", false}, // plain HTTP sent to a FakeTLS server
		{"http", false},
		{"http", true},
	}
	for kind, base := range inbounds {
		for _, tc := range cases {
			name := fmt.Sprintf("%s/%s/decoy-tls=%v", kind, tc.mode, tc.decoyTLS)
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				_, fallback := startDecoy(t, tc.decoyTLS)
				router := &fallbackRouter{testRouter: newTestRouter(), fallback: fallback.Build()}
				options := base
				options.ObfsMode = tc.mode
				options.ObfsFallback = &fallback
				port := startShadowsocksInboundWithRouter(t, router, options)

				require.Equal(t, "decoy site 127.0.0.1:"+fmt.Sprint(port)+"/probe", probe(t, port, tc.decoyTLS))
				router.mu.Lock()
				md := router.metadata[0]
				router.mu.Unlock()
				require.Equal(t, "ss-in", md.Inbound)
				require.Equal(t, fallback.Build(), md.Destination)

				if kind == "single" {
					// A real obfs client on the same port still reaches Shadowsocks.
					pluginOpts := "obfs=" + tc.mode + ";obfs-host=www.example.com"
					require.NoError(t, dialShadowsocks(t, port, "pass", "obfs-local", pluginOpts, "through obfs"))
				}
			})
		}
	}
}

func TestH_ShadowsocksObfsFallbackOptions(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	_, err := NewInbound(context.Background(), newTestRouter(), logger, "ss-in", option.ShadowsocksInboundOptions{
		Method: "aes-128-gcm", Password: "p", ObfsFallback: &option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
	})
	require.ErrorContains(t, err, "obfs_fallback requires obfs_mode")
	_, err = NewInbound(context.Background(), newTestRouter(), logger, "ss-in", option.ShadowsocksInboundOptions{
		Method: "aes-128-gcm", Password: "p", ObfsMode: "tls", ObfsFallback: &option.ServerOptions{Server: "127.0.0.1"},
	})
	require.ErrorContains(t, err, "invalid obfs_fallback address")
	in, err := NewInbound(context.Background(), newTestRouter(), logger, "ss-in", option.ShadowsocksInboundOptions{
		Method: "aes-128-gcm", Password: "p", ObfsMode: "tls", ObfsFallback: &option.ServerOptions{Server: "decoy.example.com", ServerPort: 443},
	})
	require.NoError(t, err)
	require.NoError(t, htest.Close(in))
}

// Without obfs_fallback a probe is still just closed, as before.
func TestH_ShadowsocksObfsNoFallbackClosesProbe(t *testing.T) {
	t.Parallel()
	router, port := startShadowsocksInbound(t, option.ShadowsocksInboundOptions{Method: "aes-128-gcm", Password: "p", ObfsMode: "tls"})
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	_, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/", port))
	require.Error(t, err)
	select {
	case <-router.routed:
		t.Fatal("probe was routed without obfs_fallback")
	default:
	}
}

type capturingConn struct {
	net.Conn
	sent []byte
}

func (c *capturingConn) Write(b []byte) (int, error) {
	c.sent = append(c.sent, b...)
	return c.Conn.Write(b)
}

// startRawDecoy accepts one connection, reports what it received and answers "DECOY".
func startRawDecoy(t *testing.T) (option.ServerOptions, chan []byte) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	received := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		var got []byte
		chunk := make([]byte, 4096)
		for {
			n, err := conn.Read(chunk)
			got = append(got, chunk[:n]...)
			if err != nil || len(got) >= 64 {
				break
			}
		}
		received <- got
		conn.Write([]byte("DECOY"))
	}()
	return option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(listener.Addr().(*net.TCPAddr).Port)}, received
}

// A client that passes obfs but fails Shadowsocks authentication gets the decoy,
// and the decoy sees exactly the bytes the client sent.
func TestH_ShadowsocksObfsFallbackAfterObfs(t *testing.T) {
	t.Parallel()
	inbounds := map[string]option.ShadowsocksInboundOptions{
		"single": {Method: "aes-128-gcm", Password: "pass"},
		"multi":  {Method: "aes-128-gcm", Users: []option.ShadowsocksUser{{Name: "u", Password: "pass"}}},
		"multi-2022": {
			Method:   "2022-blake3-aes-128-gcm",
			Password: "AAAAAAAAAAAAAAAAAAAAAA==",
			Users:    []option.ShadowsocksUser{{Name: "u", Password: "AAAAAAAAAAAAAAAAAAAAAA=="}},
		},
		"relay": {
			Method:       "2022-blake3-aes-128-gcm",
			Password:     "AAAAAAAAAAAAAAAAAAAAAA==",
			Destinations: []option.ShadowsocksDestination{{Name: "d", Password: "AAAAAAAAAAAAAAAAAAAAAA==", ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1}}},
		},
	}
	for kind, base := range inbounds {
		for _, mode := range []string{"http", "tls"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				t.Parallel()
				fallback, received := startRawDecoy(t)
				router := &fallbackRouter{testRouter: newTestRouter(), fallback: fallback.Build()}
				options := base
				options.ObfsMode = mode
				options.ObfsFallback = &fallback
				port := startShadowsocksInboundWithRouter(t, router, options)

				rawConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
				require.NoError(t, err)
				defer rawConn.Close()
				rawConn.SetDeadline(time.Now().Add(5 * time.Second))
				captured := &capturingConn{Conn: rawConn}
				var client net.Conn
				if mode == "http" {
					client = obfs.NewHTTPObfs(captured, "www.example.com", "443")
				} else {
					client = obfs.NewTLSObfs(captured, "www.example.com")
				}
				// Valid obfs, but the payload is not a Shadowsocks stream for this server.
				_, err = client.Write(bytes.Repeat([]byte("not shadowsocks "), 8))
				require.NoError(t, err)

				select {
				case got := <-received:
					require.Equal(t, captured.sent, got)
				case <-time.After(5 * time.Second):
					t.Fatal("decoy received nothing")
				}
				reply := make([]byte, 5)
				_, err = io.ReadFull(rawConn, reply)
				require.NoError(t, err)
				require.Equal(t, "DECOY", string(reply))
			})
		}
	}
}

package shadowsocks

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
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
			require.NoError(t, in.Close())
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
	require.NoError(t, in.Start(adapter.StartStateStart))
	t.Cleanup(func() { in.Close() })
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

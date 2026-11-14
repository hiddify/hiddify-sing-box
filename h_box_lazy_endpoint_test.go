//go:build with_wireguard

package box_test

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func hLazyEndpointConfig(t *testing.T, peerPort, listenPort int, lazy bool) string {
	t.Helper()
	privateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	peerKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	endpoint := func(tag, extra string) string {
		return `{
			"type": "wireguard", "tag": "` + tag + `", "lazy": ` + strconv.FormatBool(lazy) + extra + `,
			"address": ["172.16.0.2/32"],
			"private_key": "` + privateKey.String() + `",
			"peers": [{
				"address": "127.0.0.1", "port": ` + strconv.Itoa(peerPort) + `,
				"public_key": "` + peerKey.PublicKey().String() + `",
				"allowed_ips": ["0.0.0.0/0"]
			}]
		}`
	}
	return `{
		"log": {"disabled": true},
		"endpoints": [
			` + endpoint("wg", "") + `,
			` + endpoint("wg-server", `, "listen_port": `+strconv.Itoa(listenPort)) + `
		],
		"outbounds": [{"type": "selector", "tag": "select", "outbounds": ["wg", "wg-server"]}],
		"experimental": {"monitoring": {"urls": ["http://10.0.0.1/none"], "interval": "1h", "url_test_timeout": "1s"}}
	}`
}

// A lazy WireGuard client is in the endpoints from the start with no tunnel behind it; the first
// connection creates the real endpoint, whose handshake reaches the peer, and it goes again when
// nothing uses it. A WireGuard that listens is a server: it is created as it is, lazy or not.
func TestH_LazyEndpointInBox(t *testing.T) {
	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer peer.Close()
	peerPort := int(M.SocksaddrFromNet(peer.LocalAddr()).Port)
	listenPort := hFreeUDPPort(t)
	ctx := include.Context(context.Background())
	options := hParseOptions(t, ctx, hLazyEndpointConfig(t, peerPort, listenPort, true))
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	t.Cleanup(func() { instance.Close() })
	require.NoError(t, instance.Start())

	endpoint, loaded := instance.Endpoint().Get("wg")
	require.True(t, loaded)
	wg, isLazy := endpoint.(adapter.LazyOutbound)
	require.True(t, isLazy, "a client endpoint can be lazy")
	require.Equal(t, "wireguard", wg.Type(), "the type of what it stands for")
	// the monitoring tests it at start; once its test is over it goes (keep top unloads the ones
	// at rest, as here)
	require.Eventually(t, func() bool {
		wg.Unload()
		return !wg.Loaded()
	}, 20*time.Second, 10*time.Millisecond, "nothing stays created for one that is not used")
	require.Same(t, endpoint, hOutbound(t, instance, "wg"), "found by its tag as an outbound")
	server, _ := instance.Endpoint().Get("wg-server")
	_, isLazy = server.(adapter.LazyOutbound)
	require.False(t, isLazy, "a WireGuard that listens is a server, never lazy")

	dialed := make(chan struct{})
	go func() {
		defer close(dialed)
		dialCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if conn, err := wg.DialContext(dialCtx, N.NetworkTCP, M.ParseSocksaddr("10.0.0.1:80")); err == nil {
			conn.Close()
		}
	}()
	require.Eventually(t, wg.Loaded, 2*time.Second, time.Millisecond, "created by the first connection")
	buf := make([]byte, 2048)
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, _, err := peer.ReadFrom(buf)
	require.NoError(t, err, "the real endpoint's handshake reaches the peer")
	require.Equal(t, 148, n, "a WireGuard handshake initiation")
	<-dialed
	require.Eventually(t, func() bool {
		wg.Unload()
		return !wg.Loaded()
	}, 10*time.Second, 20*time.Millisecond, "closed once nothing goes through it")

	// the same options again: nothing is touched
	same := options
	result, err := instance.HotReloadWithResult(context.Background(), &same)
	require.NoError(t, err)
	require.True(t, result.IsEmpty())
	current, _ := instance.Endpoint().Get("wg")
	require.Same(t, endpoint, current)

	// no longer lazy: replaced by the real endpoint
	eager := hParseOptions(t, ctx, hLazyEndpointConfig(t, peerPort, listenPort, false))
	result, err = instance.HotReloadWithResult(context.Background(), &eager)
	require.NoError(t, err)
	require.Contains(t, result.Outbounds.Replaced, "wg")
	current, _ = instance.Endpoint().Get("wg")
	_, isLazy = current.(adapter.LazyOutbound)
	require.False(t, isLazy)
}

package box_test

import (
	"context"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/hiddify/warpscan"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/wireguard-go/hiddify"

	"github.com/stretchr/testify/require"
)

// hWireGuardServer starts a WireGuard endpoint that accepts clientPublic and returns its port
// and public key.
func hWireGuardServer(t *testing.T, clientPublic string, echoAddress ...string) (uint16, string) {
	t.Helper()
	route := `"final": "direct"`
	if len(echoAddress) > 0 {
		echo := M.ParseSocksaddr(echoAddress[0])
		route = `"rules": [{"inbound": ["server"], "action": "route-options", "override_address": "` + echo.AddrString() + `", "override_port": ` + strconv.Itoa(int(echo.Port)) + `}]`
	}
	serverPrivate, serverPublic := hWireGuardKey(t)
	port := hFreeUDPPort(t)
	hStartInteropBox(t, `{
		"log": {"disabled": true},
		"endpoints": [{"type": "wireguard", "tag": "server", "address": ["172.16.9.1/32"], "private_key": "`+serverPrivate+`",
			"listen_port": `+strconv.Itoa(port)+`,
			"peers": [{"public_key": "`+clientPublic+`", "allowed_ips": ["172.16.9.2/32"]}]}],
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"route": {`+route+`}
	}`, nil)
	return uint16(port), serverPublic
}

// The scanner's WireGuard probe completes a real handshake: the server only answers a valid
// initiation, and the probe verifies the response.
func TestH_WARPScannerWireGuardProbe(t *testing.T) {
	clientPrivate, clientPublic := hWireGuardKey(t)
	port, serverPublic := hWireGuardServer(t, clientPublic)
	probe, err := warpscan.WireGuardProbe(N.SystemDialer, clientPrivate, serverPublic, hiddify.NoiseOptions{})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rtt, err := probe(ctx, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port))
	require.NoError(t, err)
	require.Greater(t, rtt, time.Duration(0))

	// a key the server does not know gets no answer
	otherPrivate, _ := hWireGuardKey(t)
	stranger, err := warpscan.WireGuardProbe(N.SystemDialer, otherPrivate, serverPublic, hiddify.NoiseOptions{})
	require.NoError(t, err)
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer shortCancel()
	_, err = stranger(shortCtx, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port))
	require.Error(t, err)

	// noise packets before the initiation do not stop the handshake
	noisy, err := warpscan.WireGuardProbe(N.SystemDialer, clientPrivate, serverPublic, hiddify.NoiseOptions{FakePacket: hiddify.FakePacketOptions{
		Enabled: true, Count: hiddify.Range{From: 2, To: 3}, Size: hiddify.Range{From: 20, To: 40}, Delay: hiddify.Range{From: 1, To: 5},
	}})
	require.NoError(t, err)
	_, err = noisy(ctx, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port))
	require.NoError(t, err)
}

// A WARP endpoint whose profile endpoint is dead finds the server with its scanner, carries
// traffic through it, and remembers it: the next run reaches it even when the scan ranges no
// longer include it.
func TestH_WARPEndpointScanner(t *testing.T) {
	echoAddress := hStartEcho(t)
	clientPrivate, clientPublic := hWireGuardKey(t)
	port, serverPublic := hWireGuardServer(t, clientPublic, echoAddress)
	deadPort := hFreeUDPPort(t)
	cachePath := filepath.Join(t.TempDir(), "cache.db")
	run := func(cidr string) {
		ctx := include.Context(context.Background())
		options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
			"log": {"disabled": true},
			"experimental": {"cache_file": {"enabled": true, "path": "`+cachePath+`"}},
			"endpoints": [{"type": "warp", "tag": "warp",
				"private_key": "`+clientPrivate+`",
				"interface": {"addresses": {"v4": "172.16.9.2"}},
				"peers": [{"public_key": "`+serverPublic+`", "endpoint": {"host": "127.0.0.1", "ports": [`+strconv.Itoa(deadPort)+`]}}],
				"scanner": {"enabled": true, "cidrs": ["`+cidr+`"], "ports": [`+strconv.Itoa(deadPort)+`, `+strconv.Itoa(int(port))+`], "timeout": "500ms"}}],
			"outbounds": [{"type": "direct"}]
		}`))
		require.NoError(t, err)
		instance, err := box.New(box.Options{Context: ctx, Options: options})
		require.NoError(t, err)
		defer instance.Close()
		require.NoError(t, instance.Start())
		endpoint, _ := instance.Endpoint().Get("warp")
		var conn net.Conn
		require.Eventually(t, func() bool {
			dialCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err = endpoint.DialContext(dialCtx, N.NetworkTCP, M.ParseSocksaddr("10.9.9.9:80"))
			return err == nil
		}, 10*time.Second, 100*time.Millisecond, "no connection through the scanned endpoint")
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write([]byte("ping"))
		require.NoError(t, err)
		reply := make([]byte, 4)
		_, err = io.ReadFull(conn, reply)
		require.NoError(t, err)
		require.Equal(t, "ping", string(reply))
	}
	run("127.0.0.1/32")
	// the server is not in this range: only the saved endpoint can answer
	run("192.0.2.1/32")
}

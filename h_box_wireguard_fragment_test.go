package box_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// WireGuard lets the kernel fragment its UDP packets, as official WireGuard does. With DF set, a
// packet larger than the path MTU (here an MTU of 20000 over a 16384 loopback; in practice a
// tunnel inside another tunnel) is dropped and large transfers stall.
func TestH_WireGuardPacketsMayFragment(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	serverPrivate, serverPublic := hWireGuardKey(t)
	clientPrivate, clientPublic := hWireGuardKey(t)
	serverPort := hFreeUDPPort(t)
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
		"log": {"disabled": true},
		"endpoints": [
			{"type": "wireguard", "tag": "server", "mtu": 20000, "address": ["10.77.0.1/32"], "private_key": "`+serverPrivate+`",
				"listen_port": `+strconv.Itoa(serverPort)+`,
				"peers": [{"public_key": "`+clientPublic+`", "allowed_ips": ["10.77.0.2/32"]}]},
			{"type": "wireguard", "tag": "client", "mtu": 20000, "address": ["10.77.0.2/32"], "private_key": "`+clientPrivate+`",
				"peers": [{"address": "127.0.0.1", "port": `+strconv.Itoa(serverPort)+`, "public_key": "`+serverPublic+`",
					"allowed_ips": ["10.77.0.1/32"], "persistent_keepalive_interval": 1}]}
		],
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"route": {"rules": [{"inbound": ["server"], "action": "route-options", "override_address": "127.0.0.1",
			"override_port": `+strconv.Itoa(echo.Addr().(*net.TCPAddr).Port)+`}], "final": "direct"}
	}`))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	defer instance.Close()
	require.NoError(t, instance.Start())
	client, loaded := instance.Endpoint().Get("client")
	require.True(t, loaded)
	dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(dialCtx, N.NetworkTCP, M.ParseSocksaddr("10.77.0.1:80"))
	require.NoError(t, err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	payload := bytes.Repeat([]byte("0123456789abcdef"), 16384)
	go conn.Write(payload)
	reply := make([]byte, len(payload))
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err, "large packets did not get through")
	require.Equal(t, payload, reply)
}

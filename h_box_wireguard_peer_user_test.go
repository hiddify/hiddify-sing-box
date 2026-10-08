//go:build with_wireguard

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
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func hStartBox(t *testing.T, config string) *box.Box {
	t.Helper()
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	t.Cleanup(func() { instance.Close() })
	require.NoError(t, instance.Start())
	return instance
}

func hFreeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

type hWireGuardUsers struct {
	// send echoes payload through the tunnel of "alice" or "bob"
	send func(client string, payload []byte) error
}

// hWireGuardUserSetup starts a WireGuard server with two peers, alice (username "alice") and bob
// (no username), and a client box for each. The server reaches a local echo service at its tunnel
// address 10.9.0.1. serverExtra is added to the server config (top-level fields, with a leading
// comma); routeRules are the server's route rules.
func hWireGuardUserSetup(t *testing.T, serverExtra string, routeRules string) hWireGuardUsers {
	t.Helper()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { echo.Close() })
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
	echoPort := M.SocksaddrFromNet(echo.Addr()).Port

	serverKey, _ := wgtypes.GeneratePrivateKey()
	aliceKey, _ := wgtypes.GeneratePrivateKey()
	bobKey, _ := wgtypes.GeneratePrivateKey()
	serverPort := hFreeUDPPort(t)

	hStartBox(t, `{
		"log": {"disabled": true},
		"endpoints": [{
			"type": "wireguard",
			"tag": "wg-server",
			"address": ["10.9.0.1/24"],
			"private_key": "`+serverKey.String()+`",
			"listen_port": `+strconv.Itoa(serverPort)+`,
			"peers": [
				{"name": "alice", "public_key": "`+aliceKey.PublicKey().String()+`", "allowed_ips": ["10.9.0.2/32"]},
				{"public_key": "`+bobKey.PublicKey().String()+`", "allowed_ips": ["10.9.0.3/32"]}
			]
		}],
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"route": {"rules": `+routeRules+`}`+serverExtra+`
	}`)

	clients := map[string]adapter.Endpoint{}
	for name, client := range map[string]struct {
		key     wgtypes.Key
		address string
	}{"alice": {aliceKey, "10.9.0.2"}, "bob": {bobKey, "10.9.0.3"}} {
		instance := hStartBox(t, `{
			"log": {"disabled": true},
			"endpoints": [{
				"type": "wireguard",
				"tag": "wg",
				"address": ["`+client.address+`/32"],
				"private_key": "`+client.key.String()+`",
				"peers": [{"address": "127.0.0.1", "port": `+strconv.Itoa(serverPort)+`, "public_key": "`+serverKey.PublicKey().String()+`", "allowed_ips": ["0.0.0.0/0"]}]
			}]
		}`)
		endpoint, loaded := instance.Endpoint().Get("wg")
		require.True(t, loaded, name)
		clients[name] = endpoint
	}

	return hWireGuardUsers{send: func(client string, payload []byte) error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		// the server's tunnel address; the server endpoint maps it to its own 127.0.0.1
		conn, err := clients[client].DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("10.9.0.1", echoPort))
		if err != nil {
			return err
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		go conn.Write(payload)
		reply := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, reply); err != nil {
			return err
		}
		if !bytes.Equal(reply, payload) {
			return io.ErrUnexpectedEOF
		}
		return nil
	}}
}

// A WireGuard server sets the peer's username on its connections: a route rule on auth_user only
// lets alice through, so bob (a peer without that username) is rejected.
func TestH_WireGuardPeerUsername(t *testing.T) {
	users := hWireGuardUserSetup(t, "", `[{"auth_user": ["alice"], "outbound": "direct"}, {"action": "reject"}]`)
	require.Eventually(t, func() bool { return users.send("alice", []byte("ping")) == nil }, 10*time.Second, 200*time.Millisecond,
		"alice's connection must be accounted to alice and pass the auth_user rule")
	require.Error(t, users.send("bob", []byte("ping")), "bob has no username and must be rejected")
}

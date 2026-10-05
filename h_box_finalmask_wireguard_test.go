//go:build with_wireguard

package box_test

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/hiddify/finalmask"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WireGuard packets leave through the udp final mask: the server sees salamander-masked
// packets that unmask to a WireGuard handshake initiation.
func TestH_WireGuardEndpointFinalMask(t *testing.T) {
	const udpMask = `{"udp":[{"type":"salamander","settings":{"password":"secret"}}]}`
	rawServer, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer rawServer.Close()
	var serverOptions option.FinalMaskOptions
	require.NoError(t, json.Unmarshal([]byte(udpMask), &serverOptions))
	serverMasks, err := finalmask.Build(&serverOptions)
	require.NoError(t, err)

	privateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	peerKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	config := `{
		"log": {"disabled": true},
		"endpoints": [{
			"type": "wireguard",
			"tag": "wg",
			"address": ["172.16.0.2/32"],
			"private_key": "` + privateKey.String() + `",
			"final_mask": ` + udpMask + `,
			"peers": [{
				"address": "127.0.0.1",
				"port": ` + strconv.Itoa(int(M.SocksaddrFromNet(rawServer.LocalAddr()).Port)) + `,
				"public_key": "` + peerKey.PublicKey().String() + `",
				"allowed_ips": ["0.0.0.0/0"]
			}]
		}]
	}`
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	defer instance.Close()
	require.NoError(t, instance.Start())

	endpoint, loaded := instance.Endpoint().Get("wg")
	require.True(t, loaded)
	go func() {
		dialCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err := endpoint.DialContext(dialCtx, N.NetworkTCP, M.ParseSocksaddr("10.0.0.1:80"))
		if err == nil {
			conn.Close()
		}
	}()

	buf := make([]byte, 2048)
	rawServer.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, addr, err := rawServer.ReadFrom(buf)
	require.NoError(t, err)
	// unmasked, a WireGuard handshake initiation is 148 bytes starting with type 1
	require.NotEqual(t, 148, n, "packet left without the mask")
	masked := append([]byte(nil), buf[:n]...)

	replay, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer replay.Close()
	unmasker, err := serverMasks.UDP.WrapPacketConnServer(replay)
	require.NoError(t, err)
	sender, err := net.Dial("udp", replay.LocalAddr().String())
	require.NoError(t, err)
	defer sender.Close()
	_, err = sender.Write(masked)
	require.NoError(t, err)
	unmasker.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err = unmasker.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, 148, n, "unmasked packet from %s", addr)
	require.Equal(t, byte(1), buf[0])
}

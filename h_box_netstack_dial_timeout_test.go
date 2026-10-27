package box_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"strconv"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
)

func hWireGuardKey(t *testing.T) (private string, public string) {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	publicKey, err := curve25519.X25519(key, curve25519.Basepoint)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(key), base64.StdEncoding.EncodeToString(publicKey)
}

// A TCP dial through a WireGuard endpoint whose peer never answers must give up after the TCP
// timeout, as a direct dial does, instead of retrying SYN in the netstack for about a minute.
func TestH_WireGuardDialGivesUpAfterTCPTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the TCP timeout")
	}
	t.Parallel()
	silentPeer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer silentPeer.Close()
	privateKey, _ := hWireGuardKey(t)
	_, peerPublicKey := hWireGuardKey(t)
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
		"log": {"disabled": true},
		"endpoints": [{"type": "wireguard", "tag": "wg", "address": ["172.16.0.2/32"], "private_key": "`+privateKey+`",
			"peers": [{"address": "127.0.0.1", "port": `+strconv.Itoa(silentPeer.LocalAddr().(*net.UDPAddr).Port)+`,
				"public_key": "`+peerPublicKey+`", "allowed_ips": ["0.0.0.0/0"]}]}],
		"outbounds": [{"type": "direct", "tag": "direct"}]
	}`))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	defer instance.Close()
	require.NoError(t, instance.Start())
	endpoint, loaded := instance.Endpoint().Get("wg")
	require.True(t, loaded)
	result := make(chan error, 1)
	start := time.Now()
	go func() {
		conn, err := endpoint.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("10.255.0.1:80"))
		if conn != nil {
			conn.Close()
		}
		result <- err
	}()
	select {
	case err := <-result:
		require.Error(t, err)
		require.Less(t, time.Since(start), C.TCPTimeout+3*time.Second)
	case <-time.After(C.TCPTimeout + 5*time.Second):
		t.Fatal("the netstack dial outlived the TCP timeout")
	}
}

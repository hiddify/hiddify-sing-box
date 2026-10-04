//go:build with_wireguard

package box_test

import (
	"context"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// The WARP endpoint starts its inner WireGuard endpoint asynchronously; it must run every
// start stage (the WireGuard device is created in StartStateInitialize), otherwise the
// background start panics with a nil tun device and kills the process.
func TestH_WARPEndpointAsyncStart(t *testing.T) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	peerKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	config := `{
		"log": {"disabled": true},
		"endpoints": [{
			"type": "warp",
			"tag": "warp",
			"private_key": "` + privateKey.String() + `",
			"interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700:110:8a36::2"}},
			"peers": [{"public_key": "` + peerKey.PublicKey().String() + `", "endpoint": {"host": "127.0.0.1", "ports": [2408]}}]
		}]
	}`
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	defer instance.Close()
	require.NoError(t, instance.Start())

	warp, loaded := instance.Endpoint().Get("warp")
	require.True(t, loaded)
	require.Eventually(t, func() bool {
		dialCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		conn, err := warp.DialContext(dialCtx, N.NetworkTCP, M.ParseSocksaddr("127.0.0.1:9"))
		if conn != nil {
			conn.Close()
		}
		// once published, the inner endpoint is used (and times out without a real peer)
		return err == nil || !strings.Contains(err.Error(), "endpoint not initialized")
	}, 5*time.Second, 100*time.Millisecond, "WARP endpoint was never started")
}

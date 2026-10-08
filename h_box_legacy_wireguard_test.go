//go:build with_wireguard

package box_test

import (
	"context"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// the wireguard_legacy outbound starts without crashing (it skipped creating its device)
func TestH_LegacyWireGuardOutboundStarts(t *testing.T) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	peerKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
		"log": {"disabled": true},
		"outbounds": [{
			"type": "wireguard_legacy", "tag": "wg", "server": "127.0.0.1", "server_port": 51820,
			"local_address": "10.0.0.2/32", "private_key": "`+privateKey.String()+`",
			"peer_public_key": "`+peerKey.PublicKey().String()+`", "mtu": 1380
		}]
	}`))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	defer instance.Close()
	require.NoError(t, instance.Start())
	outbound, loaded := instance.Outbound().Outbound("wg")
	require.True(t, loaded)
	require.Equal(t, "wireguard", outbound.Type())
}

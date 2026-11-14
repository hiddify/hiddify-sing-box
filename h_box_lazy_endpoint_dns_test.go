//go:build with_openvpn

package box_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	stdjson "encoding/json"
	"strings"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"

	"github.com/stretchr/testify/require"
)

func hOpenVPNStaticKey(t *testing.T) []string {
	t.Helper()
	material := make([]byte, 256)
	_, err := rand.Read(material)
	require.NoError(t, err)
	hexKey := hex.EncodeToString(material)
	lines := []string{"-----BEGIN OpenVPN Static key V1-----"}
	for i := 0; i < len(hexKey); i += 32 {
		lines = append(lines, hexKey[i:i+32])
	}
	return append(lines, "-----END OpenVPN Static key V1-----")
}

// A DNS server that resolves through a lazy OpenVPN endpoint holds it: the real endpoint is
// created at the start, from the config's own options, and runs as without lazy. Another lazy
// OpenVPN endpoint, which nothing holds, stays a stand-in.
func TestH_LazyEndpointHeldByDNSServer(t *testing.T) {
	key, err := stdjson.Marshal(hOpenVPNStaticKey(t))
	require.NoError(t, err)
	endpoint := func(tag string) string {
		return `{"type": "openvpn-client", "tag": "` + tag + `", "lazy": true,
			"server": "127.0.0.1", "server_port": 1, "mode": "static_key", "network": "tcp",
			"address": ["10.8.0.2/30"], "peer_address": "10.8.0.1", "topology": "p2p",
			"static_key": ` + string(key) + `, "key_direction": "client", "cipher": "AES-256-CBC", "auth": "SHA256"}`
	}
	config := `{
		"log": {"disabled": true},
		"dns": {"servers": [{"type": "openvpn", "tag": "vpn-dns", "endpoint": "vpn"}]},
		"endpoints": [` + endpoint("vpn") + `, ` + endpoint("other") + `],
		"experimental": {"monitoring": {"urls": ["http://10.0.0.1/none"], "interval": "1h", "url_test_timeout": "1s"}}
	}`
	ctx := include.Context(context.Background())
	options := hParseOptions(t, ctx, strings.TrimSpace(config))
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err, "the DNS server finds its endpoint")
	t.Cleanup(func() { instance.Close() })
	require.NoError(t, instance.Start())

	vpn, _ := instance.Endpoint().Get("vpn")
	held, isLazy := vpn.(adapter.HeldLazy)
	require.True(t, isLazy, "lazy, as asked")
	require.True(t, held.Held(), "held by its DNS server")
	require.True(t, held.Loaded(), "its real one runs")
	held.Unload()
	require.True(t, held.Loaded(), "never unloaded while held")
	other, _ := instance.Endpoint().Get("other")
	require.False(t, other.(adapter.HeldLazy).Held())
}

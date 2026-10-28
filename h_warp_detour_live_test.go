package box_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

type hWARPVariant struct {
	name string
	// warp is the warp endpoint, or the masque outbound when outbound is set, with DETOUR where
	// the detour tag goes
	warp     string
	outbound bool
	display  string
}

var hWARPVariants = []hWARPVariant{
	{"wireguard", `{"type": "warp", "tag": "warp", "detour": "DETOUR", "unique_identifier": "live-wg"}`, false, "WARP · WG"},
	{"awg", `{"type": "warp", "tag": "warp", "detour": "DETOUR", "unique_identifier": "live-wg", "awg": {"jc": 4, "jmin": 40, "jmax": 70}}`, false, "WARP · AWG"},
	{"masque-h3", `{"type": "warp", "tag": "warp", "detour": "DETOUR", "unique_identifier": "live-masque", "masque": {"vhttp": "h3"}}`, false, "WARP · MASQUE"},
	{"masque-h2", `{"type": "warp", "tag": "warp", "detour": "DETOUR", "unique_identifier": "live-masque", "masque": {"vhttp": "h2"}}`, false, "WARP · MASQUE"},
	{"masque-auto", `{"type": "warp", "tag": "warp", "detour": "DETOUR", "unique_identifier": "live-masque", "masque": {"enabled": true}}`, false, "WARP · MASQUE"},
	{"masque-outbound", `{"type": "masque", "tag": "warp", "detour": "DETOUR", "unique_identifier": "live-masque-outbound"}`, true, "WARP · MASQUE"},
}

// hWARPDetours are the outbounds WARP goes through; each reaches a server in the same box that
// goes out direct. dead is a SOCKS server that does not listen, and group a selector that starts
// on dead.
var hWARPDetours = []string{"socks", "shadowsocks", "vless", "trojan"}

const hWARPLivePassword = "warp-live-password"
const hWARPLiveUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

type hWARPBox struct {
	instance  *box.Box
	mixedPort int
	variant   hWARPVariant
	groupTag  string
}

// hStartWARPBox starts WARP (or the masque outbound) through the detour named detour.
func hStartWARPBox(t *testing.T, cachePath string, variant hWARPVariant, detour string) *hWARPBox {
	t.Helper()
	mixedPort, socksPort, ssPort, vlessPort, trojanPort, deadPort := hFreeTCPPort(t), hFreeTCPPort(t), hFreeTCPPort(t), hFreeTCPPort(t), hFreeTCPPort(t), hFreeTCPPort(t)
	port := func(port int) string { return strconv.Itoa(port) }
	// the cache file keeps a selector's choice, so each box gets its own selector
	groupTag := "d-group-" + strconv.Itoa(mixedPort)
	detourTag := "d-" + detour
	if detour == "group" {
		detourTag = groupTag
	}
	warp := strings.ReplaceAll(variant.warp, "DETOUR", detourTag)
	endpoints, extraOutbounds := `[`+warp+`]`, ""
	if variant.outbound {
		endpoints, extraOutbounds = `[]`, warp+","
	}
	level := os.Getenv("HIDDIFY_LOG")
	if level == "" {
		level = "warn"
	}
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
		"log": {"level": "`+level+`"},
		"experimental": {"cache_file": {"enabled": true, "path": "`+cachePath+`", "store_warp_config": true, "store_masque_config": true}},
		"inbounds": [
			{"type": "mixed", "tag": "user-in", "listen": "127.0.0.1", "listen_port": `+port(mixedPort)+`},
			{"type": "mixed", "tag": "socks-srv", "listen": "127.0.0.1", "listen_port": `+port(socksPort)+`},
			{"type": "shadowsocks", "tag": "ss-srv", "listen": "127.0.0.1", "listen_port": `+port(ssPort)+`, "method": "aes-128-gcm", "password": "`+hWARPLivePassword+`"},
			{"type": "vless", "tag": "vless-srv", "listen": "127.0.0.1", "listen_port": `+port(vlessPort)+`, "users": [{"uuid": "`+hWARPLiveUUID+`"}]},
			{"type": "trojan", "tag": "trojan-srv", "listen": "127.0.0.1", "listen_port": `+port(trojanPort)+`, "users": [{"password": "`+hWARPLivePassword+`"}]}
		],
		"endpoints": `+endpoints+`,
		"outbounds": [`+extraOutbounds+`
			{"type": "socks", "tag": "d-socks", "server": "127.0.0.1", "server_port": `+port(socksPort)+`},
			{"type": "shadowsocks", "tag": "d-shadowsocks", "server": "127.0.0.1", "server_port": `+port(ssPort)+`, "method": "aes-128-gcm", "password": "`+hWARPLivePassword+`"},
			{"type": "vless", "tag": "d-vless", "server": "127.0.0.1", "server_port": `+port(vlessPort)+`, "uuid": "`+hWARPLiveUUID+`", "packet_encoding": "xudp"},
			{"type": "trojan", "tag": "d-trojan", "server": "127.0.0.1", "server_port": `+port(trojanPort)+`, "password": "`+hWARPLivePassword+`"},
			{"type": "socks", "tag": "d-dead", "server": "127.0.0.1", "server_port": `+port(deadPort)+`},
			{"type": "selector", "tag": "`+groupTag+`", "outbounds": ["d-dead", "d-shadowsocks"], "default": "d-dead"},
			{"type": "direct", "tag": "direct"}
		],
		"route": {"rules": [{"inbound": ["socks-srv", "ss-srv", "vless-srv", "trojan-srv"], "outbound": "direct"}], "final": "warp"}
	}`))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	t.Cleanup(func() { instance.Close() })
	require.NoError(t, instance.Start())
	return &hWARPBox{instance: instance, mixedPort: mixedPort, variant: variant, groupTag: groupTag}
}

func (b *hWARPBox) warp() adapter.Outbound {
	if b.variant.outbound {
		outbound, _ := b.instance.Outbound().Outbound("warp")
		return outbound
	}
	endpoint, _ := b.instance.Endpoint().Get("warp")
	return endpoint
}

func (b *hWARPBox) ready() bool {
	return b.warp().IsReady()
}

func (b *hWARPBox) displayType() string {
	return b.warp().(interface{ DisplayType() string }).DisplayType()
}

// traceOK reports whether a request through the box comes out of WARP.
func (b *hWARPBox) traceOK() bool {
	proxy, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(b.mixedPort))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: 10 * time.Second}
	response, err := client.Get("https://www.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return false
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return strings.Contains(string(body), "warp=on") || strings.Contains(string(body), "warp=plus")
}

func (b *hWARPBox) requireConnected(t *testing.T) {
	t.Helper()
	require.Eventually(t, b.traceOK, 120*time.Second, 2*time.Second, "no WARP traffic through the detour")
	require.Eventually(t, b.ready, 10*time.Second, 200*time.Millisecond, "connected but not ready")
	require.Equal(t, b.variant.display, b.displayType(), "display type when connected")
}

func (b *hWARPBox) requireNeverConnected(t *testing.T, period time.Duration) {
	t.Helper()
	deadline := time.Now().Add(period)
	for time.Now().Before(deadline) {
		require.False(t, b.traceOK(), "traffic got through without the detour")
		require.False(t, b.ready(), "ready without a working detour")
		require.True(t, strings.HasPrefix(b.displayType(), b.variant.display), b.displayType())
		require.True(t, strings.HasSuffix(b.displayType(), "Connecting..."), b.displayType())
		time.Sleep(2 * time.Second)
	}
}

// WARP over WireGuard, AmneziaWG and MASQUE (through the warp endpoint, and the masque outbound),
// each through SOCKS, Shadowsocks, VLESS and Trojan: traffic goes through WARP, IsReady turns
// true once it is connected and the display type names the tunnel. Through a dead detour it never
// connects nor reports ready; through a group that moves from a dead member to a working one it
// connects once it moved.
func TestH_WARPLiveDetour(t *testing.T) {
	if os.Getenv("HIDDIFY_WARP_E2E") == "" {
		t.Skip("HIDDIFY_WARP_E2E is not set")
	}
	cachePath := filepath.Join(t.TempDir(), "cache.db")
	only := os.Getenv("HIDDIFY_WARP_VARIANT")
	onlyDetours := os.Getenv("HIDDIFY_WARP_DETOUR")
	runDetour := func(detour string) bool {
		return onlyDetours == "" || strings.Contains(","+onlyDetours+",", ","+detour+",")
	}
	for _, variant := range hWARPVariants {
		if only != "" && !strings.Contains(","+only+",", ","+variant.name+",") {
			continue
		}
		t.Run(variant.name, func(t *testing.T) {
			for _, detour := range hWARPDetours {
				if !runDetour(detour) {
					continue
				}
				t.Run(detour, func(t *testing.T) {
					hStartWARPBox(t, cachePath, variant, detour).requireConnected(t)
				})
			}
			t.Run("dead", func(t *testing.T) {
				if !runDetour("dead") {
					t.Skip()
				}
				hStartWARPBox(t, cachePath, variant, "dead").requireNeverConnected(t, 20*time.Second)
			})
			t.Run("group", func(t *testing.T) {
				if !runDetour("group") {
					t.Skip()
				}
				instance := hStartWARPBox(t, cachePath, variant, "group")
				instance.requireNeverConnected(t, 6*time.Second)
				selector, _ := instance.instance.Outbound().Outbound(instance.groupTag)
				require.True(t, selector.(*group.Selector).SelectOutbound("d-shadowsocks"))
				instance.requireConnected(t)
			})
		})
	}
}

// With the scanner on, the display type shows the endpoint it found.
func TestH_WARPLiveScannerStatus(t *testing.T) {
	if os.Getenv("HIDDIFY_WARP_E2E") == "" {
		t.Skip("HIDDIFY_WARP_E2E is not set")
	}
	cachePath := filepath.Join(t.TempDir(), "cache.db")
	for _, variant := range []hWARPVariant{
		{"wireguard", `{"type": "warp", "tag": "warp", "detour": "DETOUR", "unique_identifier": "live-wg", "scanner": {"enabled": true}}`, false, "WARP · WG"},
		{"masque", `{"type": "warp", "tag": "warp", "detour": "DETOUR", "unique_identifier": "live-masque", "masque": {"vhttp": "h3"}, "scanner": {"enabled": true}}`, false, "WARP · MASQUE"},
	} {
		t.Run(variant.name, func(t *testing.T) {
			instance := hStartWARPBox(t, cachePath, variant, "socks")
			require.Eventually(t, instance.traceOK, 180*time.Second, 2*time.Second, "no WARP traffic")
			require.Eventually(t, instance.ready, 10*time.Second, 200*time.Millisecond)
			display := instance.displayType()
			require.True(t, strings.HasPrefix(display, variant.display+" · 🔍 "), display)
			require.NotContains(t, display, "Connecting")
			require.NotContains(t, display, "Scanning")
		})
	}
}

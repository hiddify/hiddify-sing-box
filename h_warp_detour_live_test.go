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
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/hiddify/warpscan"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing/common/json"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/assert"
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
	{"auto", `{"type": "warp", "tag": "warp", "detour": "DETOUR", "unique_identifier": "live-auto", "mode": "auto", "masque": {"vhttp": "h2"}}`, false, "auto"},
	{"masque-outbound", `{"type": "masque", "tag": "warp", "detour": "DETOUR", "unique_identifier": "live-masque-outbound"}`, true, "WARP · MASQUE"},
}

// hWARPDetours are the outbounds WARP goes through; each reaches a server in the same box that
// goes out direct. dead is a SOCKS server that does not listen, and group a selector that starts
// on dead.
var hWARPDetours = []string{"socks", "shadowsocks", "vless", "trojan", "http"}

const hWARPLivePassword = "warp-live-password"
const hWARPLiveUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

type hWARPBox struct {
	instance  *box.Box
	mixedPort int
	variant   hWARPVariant
	groupTag  string
	autoTag   string
}

// hStartWARPBox starts WARP (or the masque outbound) through the detour named detour.
func hStartWARPBox(t *testing.T, cachePath string, variant hWARPVariant, detour string) *hWARPBox {
	t.Helper()
	mixedPort, socksPort, ssPort, vlessPort, trojanPort, deadPort := hFreeTCPPort(t), hFreeTCPPort(t), hFreeTCPPort(t), hFreeTCPPort(t), hFreeTCPPort(t), hFreeTCPPort(t)
	port := func(port int) string { return strconv.Itoa(port) }
	// the cache file keeps a selector's choice, so each box gets its own selector
	groupTag := "d-group-" + strconv.Itoa(mixedPort)
	detourTag := "d-" + detour
	groupDefault := "d-dead"
	autoTag := "d-auto-" + strconv.Itoa(mixedPort)
	switch detour {
	case "auto": // a URL test that moves by itself, from Shadowsocks to VLESS once Shadowsocks fails
		detourTag = autoTag
	case "group":
		detourTag = groupTag
	case "switch": // a group that starts on a working member, and moves to another
		detourTag, groupDefault = groupTag, "d-socks"
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
			{"type": "http", "tag": "d-http", "server": "127.0.0.1", "server_port": `+port(socksPort)+`},
			{"type": "socks", "tag": "d-tcp", "server": "127.0.0.1", "server_port": `+port(socksPort)+`, "version": "4a"},
			{"type": "socks", "tag": "d-dead", "server": "127.0.0.1", "server_port": `+port(deadPort)+`},
			{"type": "selector", "tag": "`+groupTag+`", "outbounds": ["d-dead", "d-shadowsocks", "d-socks", "d-http", "d-tcp"], "default": "`+groupDefault+`"},
			{"type": "urltest", "tag": "`+autoTag+`", "outbounds": ["d-shadowsocks", "d-vless"], "mode": "failover", "interval": "5s"},
			{"type": "selector", "tag": "shadowsocks-exit-`+port(mixedPort)+`", "outbounds": ["direct", "d-dead"], "default": "direct"},
			{"type": "selector", "tag": "vless-exit-`+port(mixedPort)+`", "outbounds": ["direct", "d-dead"], "default": "direct"},
			{"type": "direct", "tag": "direct"}
		],
		"route": {"rules": [{"inbound": ["ss-srv"], "outbound": "shadowsocks-exit-`+port(mixedPort)+`"}, {"inbound": ["vless-srv"], "outbound": "vless-exit-`+port(mixedPort)+`"}, {"inbound": ["socks-srv", "trojan-srv"], "outbound": "direct"}], "final": "warp"}
	}`))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	t.Cleanup(func() { instance.Close() })
	require.NoError(t, instance.Start())
	return &hWARPBox{instance: instance, mixedPort: mixedPort, variant: variant, groupTag: groupTag, autoTag: autoTag}
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
	return adapter.IsReady(b.warp())
}

func (b *hWARPBox) displayType() string {
	return adapter.DisplayType(b.warp())
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
	if b.variant.display == "auto" { // the tunnel that won the race
		require.Contains(t, []string{"WARP · WG", "WARP · AWG", "WARP · MASQUE"}, b.displayType())
	} else {
		require.Equal(t, b.variant.display, b.displayType(), "display type when connected")
	}
}

func (b *hWARPBox) requireNeverConnected(t *testing.T, period time.Duration) {
	t.Helper()
	deadline := time.Now().Add(period)
	for time.Now().Before(deadline) {
		require.False(t, b.traceOK(), "traffic got through without the detour")
		require.False(t, b.ready(), "ready without a working detour")
		require.True(t, b.variant.display == "auto" || strings.HasPrefix(b.displayType(), b.variant.display), b.displayType())
		_, mark := adapter.SplitStatus(b.displayType())
		require.NotEmpty(t, mark, "a status mark while not connected: %q", b.displayType())
		time.Sleep(2 * time.Second)
	}
}

// WARP over WireGuard, AmneziaWG and MASQUE (through the warp endpoint, and the masque outbound),
// each through SOCKS, Shadowsocks, VLESS and Trojan: traffic goes through WARP, the status turns
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
			t.Run("switch", func(t *testing.T) {
				if !runDetour("switch") {
					t.Skip()
				}
				instance := hStartWARPBox(t, cachePath, variant, "switch")
				instance.requireConnected(t)
				selector, _ := instance.instance.Outbound().Outbound(instance.groupTag)
				require.True(t, selector.(*group.Selector).SelectOutbound("d-shadowsocks"))
				// the tunnel moves to the new member: SOCKS can go away, WARP still works
				require.Eventually(t, instance.traceOK, 60*time.Second, 2*time.Second, "no WARP traffic after the switch")
				require.Eventually(t, instance.ready, 30*time.Second, 200*time.Millisecond, "not ready after the switch")
			})
			t.Run("auto-switch", func(t *testing.T) {
				// a URL test moves by itself when its member fails: WARP opens a tunnel through the new
				// member and moves to it once it connects
				if !runDetour("auto-switch") {
					t.Skip()
				}
				instance := hStartWARPBox(t, cachePath, variant, "auto")
				instance.requireConnected(t)
				auto, _ := instance.instance.Outbound().Outbound(instance.autoTag)
				from, to := monitoring.ResolveDetour(auto, N.NetworkUDP), "d-vless"
				if from == "d-vless" {
					to = "d-shadowsocks"
				}
				exit, _ := instance.instance.Outbound().Outbound(strings.TrimPrefix(from, "d-") + "-exit-" + strconv.Itoa(instance.mixedPort))
				require.True(t, exit.(*group.Selector).SelectOutbound("d-dead")) // the member stops working
				require.Eventually(t, func() bool { return monitoring.ResolveDetour(auto, N.NetworkUDP) == to }, 90*time.Second, time.Second, "the URL test did not move")
				ok := assert.Eventually(t, func() bool { return instance.ready() && instance.traceOK() }, 90*time.Second, 2*time.Second)
				require.True(t, ok, "WARP did not move with the URL test: %q", instance.displayType())
			})
			t.Run("switch-to-tcp", func(t *testing.T) {
				// a proxy without UDP carries no WireGuard nor AmneziaWG: auto mode must move to MASQUE
				// over HTTP/2, even after a handshake got through before the switch
				if !runDetour("switch-to-tcp") || variant.name != "auto" {
					t.Skip()
				}
				instance := hStartWARPBox(t, cachePath, variant, "switch")
				instance.requireConnected(t)
				selector, _ := instance.instance.Outbound().Outbound(instance.groupTag)
				require.True(t, selector.(*group.Selector).SelectOutbound("d-tcp"))
				// SOCKS4 has no UDP at all
				ok := assert.Eventually(t, func() bool { return instance.ready() && instance.displayType() == "WARP · MASQUE" && instance.traceOK() },
					90*time.Second, 2*time.Second)
				require.True(t, ok, "auto mode did not move to MASQUE behind a TCP-only proxy: %q", instance.displayType())
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

// Every noise preset gets a real WARP handshake through, as WireGuard noise and as AmneziaWG
// junk and special packets.
func TestH_WARPLiveNoisePresets(t *testing.T) {
	if os.Getenv("HIDDIFY_WARP_E2E") == "" {
		t.Skip("HIDDIFY_WARP_E2E is not set")
	}
	cachePath := filepath.Join(t.TempDir(), "cache.db")
	for _, preset := range warpscan.NoisePresets {
		noise, err := json.Marshal(preset.WireGuard())
		require.NoError(t, err)
		awg, err := json.Marshal(preset.AWG(nil))
		require.NoError(t, err)
		for _, variant := range []hWARPVariant{
			{preset.Name + "/wireguard", `{"type": "warp", "tag": "warp", "detour": "DETOUR", "unique_identifier": "live-wg", "noise": ` + string(noise) + `}`, false, "WARP · WG"},
			{preset.Name + "/awg", `{"type": "warp", "tag": "warp", "detour": "DETOUR", "unique_identifier": "live-wg", "awg": ` + string(awg) + `}`, false, "WARP · AWG"},
		} {
			t.Run(variant.name, func(t *testing.T) {
				hStartWARPBox(t, cachePath, variant, "socks").requireConnected(t)
			})
		}
	}
}

// Two warp endpoints in one box get a device each, and both connect: on one device they would
// push each other off Cloudflare. A new box gives each the device it had.
func TestH_WARPLiveTwoEndpoints(t *testing.T) {
	if os.Getenv("HIDDIFY_WARP_E2E") == "" {
		t.Skip("HIDDIFY_WARP_E2E is not set")
	}
	cachePath := filepath.Join(t.TempDir(), "cache.db")
	start := func() *box.Box {
		ctx := include.Context(context.Background())
		options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
			"log": {"level": "warn"},
			"experimental": {"cache_file": {"enabled": true, "path": "`+cachePath+`", "store_warp_config": true}},
			"endpoints": [
				{"type": "warp", "tag": "warp-a", "mode": "wg"},
				{"type": "warp", "tag": "warp-b", "mode": "wg"}
			],
			"outbounds": [{"type": "direct", "tag": "direct"}]
		}`))
		require.NoError(t, err)
		instance, err := box.New(box.Options{Context: ctx, Options: options})
		require.NoError(t, err)
		require.NoError(t, instance.Start())
		return instance
	}
	devices := func(instance *box.Box) (string, string) {
		var keys [2]string
		for i, tag := range []string{"warp-a", "warp-b"} {
			endpoint, _ := instance.Endpoint().Get(tag)
			require.Eventually(t, func() bool { return adapter.IsReady(endpoint) }, 60*time.Second, 200*time.Millisecond, tag+" not connected")
			keys[i] = endpoint.(interface{ DevicePrivateKey() string }).DevicePrivateKey()
		}
		require.NotEqual(t, keys[0], keys[1], "the two endpoints share a device")
		return keys[0], keys[1]
	}
	instance := start()
	a, b := devices(instance)
	instance.Close()
	instance = start()
	defer instance.Close()
	a2, b2 := devices(instance)
	require.Equal(t, a, a2, "warp-a takes its device again")
	require.Equal(t, b, b2, "warp-b takes its device again")
}

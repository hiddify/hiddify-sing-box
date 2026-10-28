package box_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

type hWARPVariant struct {
	name string
	// config is the warp part, with DETOUR where the detour tag goes
	config   string
	endpoint bool
}

var hWARPVariants = []hWARPVariant{
	{"wireguard", `"endpoints": [{"type": "warp", "tag": "warp", "detour": "DETOUR"}]`, true},
	{"awg", `"endpoints": [{"type": "warp", "tag": "warp", "detour": "DETOUR", "awg": {"jc": 4, "jmin": 40, "jmax": 70}}]`, true},
	{"masque-h3", `"endpoints": [], "outbounds_extra": [{"type": "masque", "tag": "warp", "detour": "DETOUR", "vhttp": "h3"}]`, false},
	{"masque-h2", `"endpoints": [], "outbounds_extra": [{"type": "masque", "tag": "warp", "detour": "DETOUR", "vhttp": "h2"}]`, false},
}

// hStartWARPWithDetour starts WARP behind a SOCKS detour into the box's own mixed inbound, which
// goes out direct; with a dead detour the SOCKS server is a closed port.
func hStartWARPWithDetour(t *testing.T, variant hWARPVariant, deadDetour bool) (*box.Box, int) {
	t.Helper()
	mixedPort, detourPort := hFreeTCPPort(t), hFreeTCPPort(t)
	socksServerPort := detourPort
	if deadDetour {
		socksServerPort = hFreeTCPPort(t) // nothing listens there
	}
	warpPart := strings.ReplaceAll(variant.config, "DETOUR", "via-socks")
	extraOutbounds := ""
	if index := strings.Index(warpPart, `, "outbounds_extra": [`); index >= 0 {
		extraOutbounds = strings.TrimSuffix(warpPart[index+len(`, "outbounds_extra": [`):], "]") + ","
		warpPart = warpPart[:index]
	}
	ctx := include.Context(context.Background())
	level := os.Getenv("HIDDIFY_LOG")
	if level == "" {
		level = "warn"
	}
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(strings.ReplaceAll(`{
		"log": {"level": "LOGLEVEL"},
		"inbounds": [
			{"type": "mixed", "tag": "user-in", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(mixedPort)+`},
			{"type": "mixed", "tag": "detour-in", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(detourPort)+`}
		],
		`+warpPart+`,
		"outbounds": [`+extraOutbounds+`
			{"type": "socks", "tag": "via-socks", "server": "127.0.0.1", "server_port": `+strconv.Itoa(socksServerPort)+`},
			{"type": "direct", "tag": "direct"}
		],
		"route": {"rules": [{"inbound": "detour-in", "outbound": "direct"}], "final": "warp"}
	}`, "LOGLEVEL", level)))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	t.Cleanup(func() { instance.Close() })
	require.NoError(t, instance.Start())
	return instance, mixedPort
}

func hWARPReady(instance *box.Box, variant hWARPVariant) bool {
	var ready interface{ IsReady() bool }
	if variant.endpoint {
		endpoint, loaded := instance.Endpoint().Get("warp")
		if !loaded {
			return false
		}
		ready = endpoint
	} else {
		outbound, loaded := instance.Outbound().Outbound("warp")
		if !loaded {
			return false
		}
		ready = outbound
	}
	return ready.(adapter.Outbound).IsReady()
}

func hWARPTraceThrough(t *testing.T, mixedPort int) string {
	proxy, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(mixedPort))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: 10 * time.Second}
	response, err := client.Get("https://www.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return ""
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return string(body)
}

// WARP over WireGuard, AmneziaWG and MASQUE, each through a detour: traffic works, IsReady turns
// true once it is connected, and with a dead detour it never connects nor reports ready.
func TestH_WARPLiveDetour(t *testing.T) {
	if os.Getenv("HIDDIFY_WARP_E2E") == "" {
		t.Skip("HIDDIFY_WARP_E2E is not set")
	}
	for _, variant := range hWARPVariants {
		t.Run(variant.name, func(t *testing.T) {
			instance, mixedPort := hStartWARPWithDetour(t, variant, false)
			require.Eventually(t, func() bool {
				trace := hWARPTraceThrough(t, mixedPort)
				return strings.Contains(trace, "warp=on") || strings.Contains(trace, "warp=plus")
			}, 120*time.Second, 2*time.Second, "no WARP traffic through the detour")
			require.Eventually(t, func() bool { return hWARPReady(instance, variant) }, 10*time.Second, 200*time.Millisecond, "connected but not ready")
		})
		t.Run(variant.name+"/dead-detour", func(t *testing.T) {
			instance, mixedPort := hStartWARPWithDetour(t, variant, true)
			deadline := time.Now().Add(20 * time.Second)
			for time.Now().Before(deadline) {
				require.Empty(t, hWARPTraceThrough(t, mixedPort), "traffic got through without the detour")
				require.False(t, hWARPReady(instance, variant), "ready without a working detour")
				time.Sleep(2 * time.Second)
			}
		})
	}
}

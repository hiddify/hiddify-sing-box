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
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// Live tests against Cloudflare: each run registers a new free WARP device. They run only with
// HIDDIFY_WARP_E2E=1.
func hWARPTrace(t *testing.T, outbound string) {
	t.Helper()
	hWARPTraceWithCache(t, outbound, filepath.Join(t.TempDir(), "cache.db"))
}

func hWARPTraceWithCache(t *testing.T, outbound string, cachePath string) {
	t.Helper()
	if os.Getenv("HIDDIFY_WARP_E2E") == "" {
		t.Skip("HIDDIFY_WARP_E2E is not set")
	}
	mixedPort := hFreeTCPPort(t)
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
		"log": {"level": "info"},
		"experimental": {"cache_file": {"enabled": true, "path": "`+cachePath+`", "store_warp_config": true, "store_masque_config": true}},
		"inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(mixedPort)+`}],
		`+outbound+`,
		"route": {"final": "warp"}
	}`))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	defer instance.Close()
	require.NoError(t, instance.Start())
	proxy, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(mixedPort))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: 10 * time.Second}
	var trace string
	require.Eventually(t, func() bool {
		response, err := client.Get("https://www.cloudflare.com/cdn-cgi/trace")
		if err != nil {
			t.Log(err)
			return false
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		trace = string(body)
		return strings.Contains(trace, "warp=on") || strings.Contains(trace, "warp=plus")
	}, 90*time.Second, 2*time.Second, "no WARP traffic")
	t.Log(trace)
}

func TestH_WARPLiveWireGuardScanner(t *testing.T) {
	hWARPTrace(t, `"endpoints": [{"type": "warp", "tag": "warp", "scanner": {"enabled": true}}]`)
}

func TestH_WARPLiveMASQUEScanner(t *testing.T) {
	hWARPTrace(t, `"outbounds": [{"type": "masque", "tag": "warp", "scanner": {"enabled": true}}]`)
}

func TestH_WARPLiveMASQUEHTTP2Scanner(t *testing.T) {
	hWARPTrace(t, `"outbounds": [{"type": "masque", "tag": "warp", "use_http2": true, "scanner": {"enabled": true}}]`)
}

// A second start reuses the saved MASQUE profile and the endpoint scores.
func TestH_WARPLiveMASQUESavedProfile(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "cache.db")
	outbound := `"outbounds": [{"type": "masque", "tag": "warp", "scanner": {"enabled": true}}]`
	hWARPTraceWithCache(t, outbound, cachePath)
	hWARPTraceWithCache(t, outbound, cachePath)
}

func TestH_WARPLiveMASQUEH3(t *testing.T) {
	hWARPTrace(t, `"outbounds": [{"type": "masque", "tag": "warp", "vhttp": "h3", "scanner": {"enabled": true}}]`)
}

func TestH_WARPLiveMASQUEH2(t *testing.T) {
	hWARPTrace(t, `"outbounds": [{"type": "masque", "tag": "warp", "vhttp": "h2"}]`)
}

// WARP with QUIC noise before each handshake; the scanner probes send it too.
func TestH_WARPLiveQUICNoise(t *testing.T) {
	hWARPTrace(t, `"endpoints": [{"type": "warp", "tag": "warp", "scanner": {"enabled": true},
		"noise": {"fake_packet": {"enabled": true, "count": {"from": 2, "to": 3}, "delay": {"from": 5, "to": 10}, "mode": "quic", "sni": "www.google.com"}}}]`)
}

// A large download through MASQUE with an MTU above 1280, over HTTP/3 and HTTP/2.
func TestH_WARPLiveMASQUEMTU(t *testing.T) {
	if os.Getenv("HIDDIFY_WARP_E2E") == "" {
		t.Skip("HIDDIFY_WARP_E2E is not set")
	}
	for _, vhttp := range []string{"h3", "h2"} {
		t.Run(vhttp, func(t *testing.T) {
			mixedPort := hFreeTCPPort(t)
			ctx := include.Context(context.Background())
			options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
				"log": {"level": "warn"},
				"inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(mixedPort)+`}],
				"outbounds": [{"type": "masque", "tag": "warp", "vhttp": "`+vhttp+`", "mtu": 1400}],
				"route": {"final": "warp"}
			}`))
			require.NoError(t, err)
			instance, err := box.New(box.Options{Context: ctx, Options: options})
			require.NoError(t, err)
			defer instance.Close()
			require.NoError(t, instance.Start())
			proxy, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(mixedPort))
			client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: 30 * time.Second}
			require.Eventually(t, func() bool {
				response, err := client.Get("https://speed.cloudflare.com/__down?bytes=2000000")
				if err != nil {
					t.Log(err)
					return false
				}
				defer response.Body.Close()
				n, err := io.Copy(io.Discard, response.Body)
				if err != nil {
					t.Log(err)
				}
				return err == nil && n == 2000000
			}, 90*time.Second, 2*time.Second)
		})
	}
}

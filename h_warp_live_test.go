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
	if os.Getenv("HIDDIFY_WARP_E2E") == "" {
		t.Skip("HIDDIFY_WARP_E2E is not set")
	}
	mixedPort := hFreeTCPPort(t)
	cachePath := filepath.Join(t.TempDir(), "cache.db")
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
		"log": {"level": "info"},
		"experimental": {"cache_file": {"enabled": true, "path": "`+cachePath+`"}},
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

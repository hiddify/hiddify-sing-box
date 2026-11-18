package box_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"

	"github.com/stretchr/testify/require"
)

// hPsiphonReloadConfig is a box with Psiphon behind a mixed inbound, in region.
func hPsiphonReloadConfig(port int, dir, region, extra string) string {
	return fmt.Sprintf(`{
	"log": {"level": "warn"},
	"inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": %d}],
	"outbounds": [{"type": "psiphon", "tag": "psiphon", "data_directory": %q, "egress_region": %q %s}],
	"route": {"final": "psiphon"},
	"experimental": {"cache_file": {"enabled": true, "path": %q}}
}`, port, dir+"/psiphon", region, extra, dir+"/cache.db")
}

// hPsiphonExit reads the country of the exit through the mixed inbound on port.
func hPsiphonExit(port int) (string, error) {
	proxy, _ := url.Parse(fmt.Sprint("http://127.0.0.1:", port))
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	response, err := client.Get("https://www.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(content), "\n") {
		if location, found := strings.CutPrefix(line, "loc="); found {
			return location, nil
		}
	}
	return "", fmt.Errorf("no loc in trace")
}

// A Psiphon config changed by a hot reload takes effect: the new outbound connects in the new
// region, the old one closes, and the box closes after. The Psiphon tunnel core keeps global
// state (its data store, its notice writer), and the replacement starts before the old one
// closes. HIDDIFY_PSIPHON_E2E=1.
func TestH_PsiphonHotReload(t *testing.T) {
	if os.Getenv("HIDDIFY_PSIPHON_E2E") == "" {
		t.Skip("set HIDDIFY_PSIPHON_E2E=1")
	}
	ctx := include.Context(context.Background())
	port := hFreeTCPPort(t)
	dir := t.TempDir()
	instance, err := box.New(box.Options{Context: ctx, Options: hParseOptions(t, ctx, hPsiphonReloadConfig(port, dir, "US", ""))})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	exitIn := func(region string, within time.Duration) {
		t.Helper()
		deadline := time.Now().Add(within)
		var last string
		for time.Now().Before(deadline) {
			location, err := hPsiphonExit(port)
			if err == nil && location == region {
				t.Log("exit in ", region)
				return
			}
			last = fmt.Sprint(location, " ", err)
			time.Sleep(2 * time.Second)
		}
		t.Fatalf("no exit in %s within %s (last: %s)", region, within, last)
	}
	exitIn("US", 3*time.Minute)

	old := hOutbound(t, instance, "psiphon")
	reload := hParseOptions(t, ctx, hPsiphonReloadConfig(port, dir, "DE", `, "scanner": {"sets": ["fastly"]}`))
	require.NoError(t, instance.HotReload(ctx, &reload))
	require.NotSame(t, old, hOutbound(t, instance, "psiphon"), "the changed outbound is replaced")
	exitIn("DE", 3*time.Minute)

	// once more, back: the core's global state survives a second replacement
	reload = hParseOptions(t, ctx, hPsiphonReloadConfig(port, dir, "US", ""))
	require.NoError(t, instance.HotReload(ctx, &reload))
	exitIn("US", 3*time.Minute)

	closed := make(chan error, 1)
	go func() { closed <- instance.Close() }()
	select {
	case <-closed:
	case <-time.After(30 * time.Second):
		t.Fatal("the box did not close")
	}
}

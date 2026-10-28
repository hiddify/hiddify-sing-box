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
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// hStartPsiphonBox starts a box that sends everything through a Psiphon outbound.
func hStartPsiphonBox(t *testing.T, dataDirectory string) (*box.Box, int) {
	t.Helper()
	mixedPort := hFreeTCPPort(t)
	level := os.Getenv("HIDDIFY_LOG")
	if level == "" {
		level = "warn"
	}
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
		"log": {"level": "`+level+`"},
		"inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(mixedPort)+`}],
		"outbounds": [
			{"type": "psiphon", "tag": "psiphon", "data_directory": "`+dataDirectory+`"},
			{"type": "direct", "tag": "direct"}
		],
		"route": {"final": "psiphon"}
	}`))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	return instance, mixedPort
}

func hTraceThrough(mixedPort int) bool {
	proxy, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(mixedPort))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: 15 * time.Second}
	response, err := client.Get("https://www.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return false
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return strings.Contains(string(body), "ip=")
}

// Once traffic goes through Psiphon, it is ready; a second box started after the first closed
// (a reload) is ready too.
func TestH_PsiphonLiveStatus(t *testing.T) {
	if os.Getenv("HIDDIFY_PSIPHON_E2E") == "" {
		t.Skip("HIDDIFY_PSIPHON_E2E is not set")
	}
	dataDirectory := filepath.Join(t.TempDir(), "psiphon")
	for round := range 2 {
		instance, mixedPort := hStartPsiphonBox(t, dataDirectory)
		require.Eventually(t, func() bool { return hTraceThrough(mixedPort) }, 3*time.Minute, 2*time.Second, "round %d: no traffic through Psiphon", round)
		outbound, _ := instance.Outbound().Outbound("psiphon")
		require.Eventually(t, func() bool { return adapter.IsReady(outbound) }, 10*time.Second, 200*time.Millisecond,
			"round %d: traffic goes through, but the status is %s (%q)", round, outbound.Status(), adapter.DisplayType(outbound))
		instance.Close()
	}
}

// Two Psiphon outbounds start together, each with its own data directory, and close.
func TestH_PsiphonTwoOutbounds(t *testing.T) {
	dataDirectory := filepath.Join(t.TempDir(), "psiphon")
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
		"log": {"disabled": true},
		"outbounds": [
			{"type": "psiphon", "tag": "psiphon-us", "egress_region": "US", "data_directory": "`+dataDirectory+`"},
			{"type": "psiphon", "tag": "psiphon-de", "egress_region": "DE", "data_directory": "`+dataDirectory+`"},
			{"type": "direct", "tag": "direct"}
		],
		"route": {"final": "direct"}
	}`))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	for _, tag := range []string{"psiphon-us", "psiphon-de"} {
		outbound, loaded := instance.Outbound().Outbound(tag)
		require.True(t, loaded)
		require.NotEqual(t, adapter.StatusFailed, outbound.Status(), tag)
		require.DirExists(t, filepath.Join(dataDirectory, tag), "a directory of its own")
	}
	require.NoError(t, instance.Close())
}

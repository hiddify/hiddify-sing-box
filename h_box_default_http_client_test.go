package box_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// A remote rule-set downloaded after start must use route.default_http_client, not a fallback
// built before the HTTP client manager started.
func TestH_RemoteRuleSetUsesDefaultHTTPClient(t *testing.T) {
	clients := make(chan string, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clients <- r.Header.Get("X-Client")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":3,"rules":[{"domain":["example.com"]}]}`))
	}))
	defer server.Close()
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(fmt.Sprintf(`{
		"log": {"disabled": true},
		"dns": {"servers": [{"type": "local", "tag": "dns"}]},
		"http_clients": [
			{"tag": "first", "domain_resolver": "dns", "headers": {"X-Client": "first"}},
			{"tag": "chosen", "domain_resolver": "dns", "headers": {"X-Client": "chosen"}}
		],
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"route": {
			"default_http_client": "chosen",
			"rule_set": [{"type": "remote", "tag": "remote", "format": "source", "url": %q}],
			"rules": [{"rule_set": "remote", "outbound": "direct"}]
		}
	}`, server.URL+"/rules.json")))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	defer instance.Close()
	require.NoError(t, instance.Start())
	select {
	case client := <-clients:
		require.Equal(t, "chosen", client)
	case <-time.After(5 * time.Second):
		t.Fatal("the rule-set was not downloaded")
	}
}

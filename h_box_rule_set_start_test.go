package box_test

import (
	"context"
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

// A remote rule-set with no cached copy must not hold the start: on a slow network its download
// kept the tunnel from coming up, and a stop had to wait for it. It is fetched once the box is up.
func TestHRemoteRuleSetDoesNotHoldStart(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select { // never answers until the test ends
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	defer close(release)

	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"route": {
			"rule_set": [{"type": "remote", "tag": "remote", "format": "source", "url": "`+server.URL+`"}],
			"rules": [{"rule_set": "remote", "outbound": "direct"}]
		}
	}`))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	defer instance.Close()

	begin := time.Now()
	require.NoError(t, instance.Start())
	require.Less(t, time.Since(begin), 2*time.Second, "the start waited for the rule-set download")
}

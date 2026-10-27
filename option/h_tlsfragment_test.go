package option_test

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// H: subscription/editor outbounds that embed dialer tls_fragment must parse as
// real outbounds, not TypeHInvalidConfig (issue #2399).
func TestDialerTLSFragmentIsAccepted(t *testing.T) {
	ctx := include.Context(context.Background())
	const config = `{
  "outbounds": [
    {
      "type": "vless",
      "tag": "xhttp-fragment",
      "server": "127.0.0.1",
      "server_port": 443,
      "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
      "tcp_fast_open": false,
      "tls_fragment": {"enabled": true, "size": "1-10", "sleep": "1-10"},
      "tls": {"enabled": true, "server_name": "example.com"},
      "transport": {"type": "xhttp", "path": "/"}
    }
  ]
}`
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
	require.NoError(t, err)
	require.Len(t, options.Outbounds, 1)

	out := options.Outbounds[0]
	require.Equal(t, C.TypeVLESS, out.Type)
	require.NotEqual(t, C.TypeHInvalidConfig, out.Type)

	opts, ok := out.Options.(*option.VLESSOutboundOptions)
	require.True(t, ok)
	require.True(t, opts.TLSFragment.Enabled)
	require.Equal(t, "1-10", opts.TLSFragment.Size)
	require.Equal(t, "1-10", opts.TLSFragment.Sleep)
}

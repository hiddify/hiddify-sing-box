package option

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestH_MigrateTLSFragment(t *testing.T) {
	fragment := &TLSFragmentOptions{Enabled: true, Size: "10-20", Sleep: "1-2"}
	options := &VLESSOutboundOptions{OutboundTLSOptionsContainer: OutboundTLSOptionsContainer{TLS: &OutboundTLSOptions{Enabled: true, TLSFragment: fragment}}}
	MigrateTLSFragment(options)
	require.Equal(t, *fragment, options.TLSFragment)

	own := TLSFragmentOptions{Enabled: true, Size: "1-2"}
	options = &VLESSOutboundOptions{OutboundTLSOptionsContainer: OutboundTLSOptionsContainer{TLS: &OutboundTLSOptions{Enabled: true, TLSFragment: fragment}}}
	options.TLSFragment = own
	MigrateTLSFragment(options)
	require.Equal(t, own, options.TLSFragment, "the dialer's own tls_fragment wins")

	MigrateTLSFragment(&VLESSOutboundOptions{}) // no tls block
}

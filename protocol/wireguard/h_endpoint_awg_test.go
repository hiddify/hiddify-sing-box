package wireguard

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// an awg block on a wireguard endpoint was silently ignored; it is refused instead
func TestH_EndpointRefusesAWGBlock(t *testing.T) {
	_, err := NewEndpoint(context.Background(), nil, log.NewNOPFactory().Logger(), "wg", option.WireGuardEndpointOptions{
		AWG: &option.AwgOptions{Jc: 3},
	})
	require.ErrorContains(t, err, `use "type": "awg"`)
}

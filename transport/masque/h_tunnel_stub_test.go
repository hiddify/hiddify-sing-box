//go:build !with_gvisor

package masque

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/stretchr/testify/require"
)

func TestH_TunnelRequiresGVisor(t *testing.T) {
	_, err := NewTunnel(context.Background(), log.NewNOPFactory().NewLogger("masque"), TunnelOptions{
		Address: []netip.Prefix{netip.MustParsePrefix("172.16.0.2/32")},
	})
	require.ErrorIs(t, err, tun.ErrGVisorNotIncluded)
	require.ErrorContains(t, err, "create MASQUE device")
}

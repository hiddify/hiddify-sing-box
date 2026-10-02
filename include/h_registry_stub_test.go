//go:build !with_wireguard || !with_awg || !with_masque

package include

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func hRequireStubError(t *testing.T, err error, tag string) {
	t.Helper()
	require.Error(t, err)
	require.ErrorContains(t, err, "not included in this build")
	require.ErrorContains(t, err, tag)
}

func TestH_StubEndpointsAndOutbounds(t *testing.T) {
	ctx := context.Background()
	logger := log.NewNOPFactory().NewLogger("test")
	if !hWithWireGuard {
		_, err := EndpointRegistry().Create(ctx, nil, logger, "warp", C.TypeWARP, &option.WARPEndpointOptions{})
		hRequireStubError(t, err, "with_wireguard")
	}
	if !hWithAwg {
		_, err := EndpointRegistry().Create(ctx, nil, logger, "awg", C.TypeAwg, &option.AwgEndpointOptions{})
		hRequireStubError(t, err, "with_awg")
	}
	if !hWithMASQUE {
		_, err := OutboundRegistry().CreateOutbound(ctx, nil, logger, "masque", C.TypeMASQUE, &option.MASQUEOutboundOptions{})
		hRequireStubError(t, err, "with_masque")
	}
}

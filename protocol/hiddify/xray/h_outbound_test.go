package xray

import (
	"context"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func TestH_NewNotImplemented(t *testing.T) {
	t.Parallel()
	ob, err := New(context.Background(), nil, log.NewNOPFactory().Logger(), "x", option.XrayOutboundOptions{})
	require.Nil(t, ob)
	require.ErrorContains(t, err, "not implemented")
}

func TestH_RegisterOutbound(t *testing.T) {
	t.Parallel()
	registry := outbound.NewRegistry()
	RegisterOutbound(registry)
	options, loaded := registry.CreateOptions(C.TypeXray)
	require.True(t, loaded)
	require.IsType(t, &option.XrayOutboundOptions{}, options)
}

func TestH_OutboundBlocks(t *testing.T) {
	t.Parallel()
	h := &Outbound{logger: log.NewNOPFactory().Logger()}
	conn, err := h.DialContext(context.Background(), "tcp", M.ParseSocksaddr("127.0.0.1:1"))
	require.Nil(t, conn)
	require.ErrorIs(t, err, syscall.EPERM)
	packetConn, err := h.ListenPacket(context.Background(), M.ParseSocksaddr("127.0.0.1:1"))
	require.Nil(t, packetConn)
	require.ErrorIs(t, err, syscall.EPERM)
}

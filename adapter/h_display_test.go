package adapter_test

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type hDisplayOutbound struct {
	outbound.Adapter
	N.Dialer
	ready   bool
	display string
}

func (o *hDisplayOutbound) IsReady() bool { return o.ready }

type hNamedOutbound struct {
	hDisplayOutbound
}

func (o *hNamedOutbound) DisplayType() string { return o.display }

// Every outbound gets the connecting mark while it is not ready, whatever its own display type.
func TestH_DisplayType(t *testing.T) {
	plain := &hDisplayOutbound{Adapter: outbound.NewAdapter(C.TypeSSH, "a", nil, nil)}
	require.Equal(t, "SSH"+C.DisplayConnecting, adapter.DisplayType(plain))
	plain.ready = true
	require.Equal(t, "SSH", adapter.DisplayType(plain))

	named := &hNamedOutbound{hDisplayOutbound{Adapter: outbound.NewAdapter(C.TypeWARP, "b", nil, nil), display: "WARP · MASQUE · 🔍 1.1.1.1:443"}}
	require.Equal(t, "WARP · MASQUE · 🔍 1.1.1.1:443"+C.DisplayConnecting, adapter.DisplayType(named))
	named.ready = true
	require.Equal(t, "WARP · MASQUE · 🔍 1.1.1.1:443", adapter.DisplayType(named))
}

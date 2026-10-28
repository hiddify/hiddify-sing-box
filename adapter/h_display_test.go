package adapter_test

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
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

func (o *hDisplayOutbound) Status() adapter.Status {
	if o.ready {
		return adapter.StatusReady
	}
	return adapter.StatusConnecting
}

type hNamedOutbound struct {
	hDisplayOutbound
}

func (o *hNamedOutbound) DisplayType() string { return o.display }

// Every outbound gets the connecting mark while it is not ready, whatever its own display type.
func TestH_DisplayType(t *testing.T) {
	plain := &hDisplayOutbound{Adapter: outbound.NewAdapter(C.TypeSSH, "a", nil, nil)}
	hRequireConnecting(t, "SSH", adapter.DisplayType(plain))
	plain.ready = true
	require.Equal(t, "SSH", adapter.DisplayType(plain))

	named := &hNamedOutbound{hDisplayOutbound{Adapter: outbound.NewAdapter(C.TypeWARP, "b", nil, nil), display: "WARP · MASQUE · 🔍 1.1.1.1:443"}}
	hRequireConnecting(t, "WARP · MASQUE · 🔍 1.1.1.1:443", adapter.DisplayType(named))
	named.ready = true
	require.Equal(t, "WARP · MASQUE · 🔍 1.1.1.1:443", adapter.DisplayType(named))
}

func hRequireConnecting(t *testing.T, base string, display string) {
	t.Helper()
	gotBase, mark := adapter.SplitStatus(display)
	require.Equal(t, base, gotBase, display)
	require.NotEmpty(t, mark, display)
}

type hDisplayEndpoint struct {
	endpoint.Adapter
	N.Dialer
	ready bool
}

func (e *hDisplayEndpoint) Status() adapter.Status {
	if e.ready {
		return adapter.StatusReady
	}
	return adapter.StatusConnecting
}
func (e *hDisplayEndpoint) Start(adapter.StartStage, *adapter.Scope) error { return nil }

// An endpoint gets the mark the same way.
func TestH_DisplayTypeEndpoint(t *testing.T) {
	ep := &hDisplayEndpoint{Adapter: endpoint.NewAdapter(C.TypeWireGuard, "wg", nil, nil)}
	var _ adapter.Endpoint = ep
	hRequireConnecting(t, "WireGuard", adapter.DisplayType(ep))
	ep.ready = true
	require.Equal(t, "WireGuard", adapter.DisplayType(ep))
}

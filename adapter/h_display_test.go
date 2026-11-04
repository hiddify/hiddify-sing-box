package adapter_test

import (
	"errors"
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
	status adapter.Status
	err    error
}

func (o *hDisplayOutbound) Status() adapter.Status { return o.status }
func (o *hDisplayOutbound) StatusError() error     { return o.err }

type hNamedOutbound struct {
	hDisplayOutbound
	display string
}

func (o *hNamedOutbound) DisplayType() string { return o.display }

// The display type says nothing the status says: no mark while not ready. A failed outbound adds
// why it failed; one that is only connecting does not, its error goes to the app on its own.
func TestH_DisplayType(t *testing.T) {
	plain := &hDisplayOutbound{Adapter: outbound.NewAdapter(C.TypeSSH, "a", nil, nil), status: adapter.StatusConnecting, err: errors.New("connection refused")}
	require.Equal(t, "SSH", adapter.DisplayType(plain))
	plain.status = adapter.StatusReady
	require.Equal(t, "SSH", adapter.DisplayType(plain))
	plain.status = adapter.StatusFailed
	require.Equal(t, "SSH: connection refused", adapter.DisplayType(plain))
	plain.err = nil
	require.Equal(t, "SSH", adapter.DisplayType(plain))

	named := &hNamedOutbound{hDisplayOutbound{Adapter: outbound.NewAdapter(C.TypeWARP, "b", nil, nil), status: adapter.StatusSearching}, "WARP · MASQUE · 🔍 1.1.1.1:443"}
	require.Equal(t, "WARP · MASQUE · 🔍 1.1.1.1:443", adapter.DisplayType(named))
	named.status, named.err = adapter.StatusFailed, errors.New("no endpoint answers")
	require.Equal(t, "WARP · MASQUE · 🔍 1.1.1.1:443: no endpoint answers", adapter.DisplayType(named))
	// a display type that already says why is not repeated
	named.display = "WARP · no endpoint answers"
	require.Equal(t, "WARP · no endpoint answers", adapter.DisplayType(named))
}

type hDisplayEndpoint struct {
	endpoint.Adapter
	N.Dialer
	status adapter.Status
}

func (e *hDisplayEndpoint) Status() adapter.Status                         { return e.status }
func (e *hDisplayEndpoint) Start(adapter.StartStage, *adapter.Scope) error { return nil }

// An endpoint is shown the same way.
func TestH_DisplayTypeEndpoint(t *testing.T) {
	ep := &hDisplayEndpoint{Adapter: endpoint.NewAdapter(C.TypeWireGuard, "wg", nil, nil), status: adapter.StatusConnecting}
	var _ adapter.Endpoint = ep
	require.Equal(t, "WireGuard", adapter.DisplayType(ep))
	ep.status = adapter.StatusFailed
	require.Equal(t, "WireGuard", adapter.DisplayType(ep), "no StatusError: nothing to add")
}

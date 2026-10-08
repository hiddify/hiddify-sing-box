package dialer

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

type hFakeOutbound struct {
	adapter.Outbound
	tag string
}

func (o *hFakeOutbound) Tag() string { return o.tag }

func (o *hFakeOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, nil
}

type hFakeOutboundManager struct {
	adapter.OutboundManager
	byTag map[string]adapter.Outbound
}

func (m *hFakeOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.byTag[tag]
	return outbound, loaded
}

// a detour follows the outbound currently registered under its tag (hot reload replaces it)
func TestH_DetourFollowsReplacedOutbound(t *testing.T) {
	first := &hFakeOutbound{tag: "proxy"}
	manager := &hFakeOutboundManager{byTag: map[string]adapter.Outbound{"proxy": first}}
	detour := NewDetour(manager, "proxy", true).(*DetourDialer)

	resolved, err := detour.Dialer()
	require.NoError(t, err)
	require.Same(t, first, resolved)

	second := &hFakeOutbound{tag: "proxy"}
	manager.byTag["proxy"] = second
	resolved, err = detour.Dialer()
	require.NoError(t, err)
	require.Same(t, second, resolved)

	delete(manager.byTag, "proxy")
	_, err = detour.Dialer()
	require.ErrorContains(t, err, "outbound detour not found: proxy")

	manager.byTag["proxy"] = first
	resolved, err = detour.Dialer()
	require.NoError(t, err)
	require.Same(t, first, resolved, "found again once it is back")
}

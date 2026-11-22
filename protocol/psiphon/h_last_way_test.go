package psiphon

import (
	"context"
	"net/netip"
	"testing"

	psiphon "github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/sagernet/sing-box/hiddify/edgescan"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

func hLastWayScanner(t *testing.T) *edgeScanner {
	store := edgescan.OpenStore(nil, t.Name())
	return &edgeScanner{
		ctx:    context.Background(),
		logger: log.NewNOPFactory().Logger(),
		store:  store,
		book:   store.Book(edgescan.KindPsiphon),
		port:   cdnPort,
	}
}

// The tunnel core's ActiveTunnel notice reaches the scanner: before, only Info notices did, so
// the protocol of a tunnel that came up was never rated, nor kept.
func TestH_PsiphonActiveTunnelReachesScanner(t *testing.T) {
	p := &Psiphon{logger: log.NewNOPFactory().Logger()}
	var seen []string
	p.onInfo = func(event NoticeEvent) { seen = append(seen, event.Type) }
	p.onNotice(NoticeEvent{Type: "ActiveTunnel", Data: map[string]interface{}{"protocol": "OSSH"}}, func() {})
	p.onNotice(NoticeEvent{Type: "Info", Data: map[string]interface{}{"message": "x"}}, func() {})
	p.onNotice(NoticeEvent{Type: "Alert", Data: map[string]interface{}{}}, func() {})
	require.Equal(t, []string{"ActiveTunnel", "Info"}, seen)
}

// A tunnel that comes up is kept as the last way: its protocol, and for a fronted one the edge
// the core connected over in that attempt.
func TestH_PsiphonRemembersWay(t *testing.T) {
	s := hLastWayScanner(t)
	s.network.Name = "wifi/IR"
	edge := edgescan.Target{AddrPort: netip.MustParseAddrPort("23.1.2.3:443"), ServerName: "a.example"}
	s.onNotice(NoticeEvent{Type: "Info", Data: map[string]interface{}{"message": `cdn fronting scan found (ip: 23\.1\.2\.3, sni: a.example)`}})
	s.onNotice(NoticeEvent{Type: "ActiveTunnel", Data: map[string]interface{}{"protocol": "FRONTED-MEEK-OSSH"}})
	way, found := s.store.LastWay(lastWayKey)
	require.True(t, found)
	require.Equal(t, "FRONTED-MEEK-OSSH", way.Method(wayProtocol))
	require.Equal(t, edge, way.Target)
	require.Equal(t, "wifi/IR", way.Network)
	score, _ := s.book.MethodScore("wifi/IR", protocolMethod("FRONTED-MEEK-OSSH"))
	require.Positive(t, score, "the protocol is rated")

	s.beginAttempt()
	s.onNotice(NoticeEvent{Type: "ActiveTunnel", Data: map[string]interface{}{"protocol": "OSSH"}})
	way, _ = s.store.LastWay(lastWayKey)
	require.Equal(t, "OSSH", way.Method(wayProtocol))
	require.False(t, way.Target.AddrPort.IsValid(), "no edge for a protocol that does not front")
}

// The first attempt of a search with a last way starts the tunnel core with it: its protocol
// first, its edge, its network, for a short attempt; what it changed is set back after.
func TestH_PsiphonUseLastWay(t *testing.T) {
	s := hLastWayScanner(t)
	h := &Outbound{logger: log.NewNOPFactory().Logger(), scanner: s, psiphon: &Psiphon{config: &psiphon.Config{}}}
	config := h.psiphon.config
	config.LimitTunnelProtocols = firstHopProtocols
	config.NetworkID = "test"
	config.EstablishTunnelTimeoutSeconds = durationToSecondsPtr(defaultEstablishTunnelTimeout)
	config.FrontedMeekCDNScanUseBuiltInSpec = true
	_, ok := h.useLastWay()
	require.False(t, ok, "nothing worked yet")

	edge := edgescan.Target{AddrPort: netip.MustParseAddrPort("151.101.1.1:443")} // fastly
	s.store.RememberWay(lastWayKey, edgescan.LastWay{Network: "wifi/IR", Target: edge, Methods: map[string]string{wayProtocol: "FRONTED-MEEK-OSSH"}})
	restore, ok := h.useLastWay()
	require.True(t, ok)
	require.Equal(t, "wifi/IR", config.NetworkID)
	require.Equal(t, []string{"FRONTED-MEEK-OSSH"}, []string(config.InitialLimitTunnelProtocols))
	require.Len(t, config.FrontedMeekDialOverrides, 1)
	require.Equal(t, []string{"151.101.1.1"}, config.FrontedMeekDialOverrides[0].DialAddresses)
	require.False(t, config.FrontedMeekCDNScanUseBuiltInSpec)
	require.Equal(t, int(lastWayAttempt.Seconds()), *config.EstablishTunnelTimeoutSeconds)

	restore()
	require.Equal(t, "test", config.NetworkID)
	require.Empty(t, config.InitialLimitTunnelProtocols)
	require.Empty(t, config.FrontedMeekDialOverrides)
	require.True(t, config.FrontedMeekCDNScanUseBuiltInSpec)
	require.Equal(t, int(defaultEstablishTunnelTimeout.Seconds()), *config.EstablishTunnelTimeoutSeconds)

	h.fixedNetworkID = true
	s.store.RememberWay(lastWayKey, edgescan.LastWay{Network: "wifi/IR", Methods: map[string]string{wayProtocol: "OSSH"}})
	_, ok = h.useLastWay()
	require.True(t, ok)
	require.Equal(t, "test", config.NetworkID, "network_id is kept")
	require.Empty(t, config.FrontedMeekDialOverrides)
	require.True(t, config.FrontedMeekCDNScanUseBuiltInSpec)

	config.LimitTunnelProtocols = chainedProtocols
	s.store.RememberWay(lastWayKey, edgescan.LastWay{Methods: map[string]string{wayProtocol: "FRONTED-MEEK-QUIC-OSSH"}})
	_, ok = h.useLastWay()
	require.False(t, ok, "a protocol the outbound no longer uses")
}

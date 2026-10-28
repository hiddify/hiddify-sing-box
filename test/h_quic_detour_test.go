package main

import (
	"net/netip"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
)

// Hysteria2, a QUIC protocol, through a proxy detour: full-size QUIC packets come back with the
// proxy's framing around them, which a reader with a buffer of one packet could not take whole.
func TestH_Hysteria2OverProxy(t *testing.T) {
	detours := map[string]option.Outbound{
		"shadowsocks": {Type: C.TypeShadowsocks, Tag: "detour", Options: &option.ShadowsocksOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: otherPort},
			Method:        "aes-128-gcm", Password: "password",
		}},
		"vless": {Type: C.TypeVLESS, Tag: "detour", Options: &option.VLESSOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: otherPort},
			UUID:          "b831381d-6324-4d53-ad4f-8cda48b30811", PacketEncoding: common.Ptr("xudp"),
		}},
		"trojan": {Type: C.TypeTrojan, Tag: "detour", Options: &option.TrojanOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: otherPort},
			Password:      "password",
		}},
	}
	servers := map[string]option.Inbound{
		"shadowsocks": {Type: C.TypeShadowsocks, Tag: "proxy-in", Options: &option.ShadowsocksInboundOptions{
			ListenOptions: option.ListenOptions{Listen: common.Ptr(badoption.Addr(netip.IPv4Unspecified())), ListenPort: otherPort},
			Method:        "aes-128-gcm", Password: "password",
		}},
		"vless": {Type: C.TypeVLESS, Tag: "proxy-in", Options: &option.VLESSInboundOptions{
			ListenOptions: option.ListenOptions{Listen: common.Ptr(badoption.Addr(netip.IPv4Unspecified())), ListenPort: otherPort},
			Users:         []option.VLESSUser{{UUID: "b831381d-6324-4d53-ad4f-8cda48b30811"}},
		}},
		"trojan": {Type: C.TypeTrojan, Tag: "proxy-in", Options: &option.TrojanInboundOptions{
			ListenOptions: option.ListenOptions{Listen: common.Ptr(badoption.Addr(netip.IPv4Unspecified())), ListenPort: otherPort},
			Users:         []option.TrojanUser{{Password: "password"}},
		}},
	}
	for _, name := range []string{"shadowsocks", "vless", "trojan"} {
		t.Run(name, func(t *testing.T) {
			testHysteria2OverProxy(t, servers[name], detours[name])
		})
	}
}

func testHysteria2OverProxy(t *testing.T, server option.Inbound, detour option.Outbound) {
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	startInstance(t, option.Options{
		Inbounds: []option.Inbound{
			{Type: C.TypeMixed, Tag: "mixed-in", Options: &option.HTTPMixedInboundOptions{ListenOptions: option.ListenOptions{
				Listen: common.Ptr(badoption.Addr(netip.IPv4Unspecified())), ListenPort: clientPort,
			}}},
			server,
			{Type: C.TypeHysteria2, Tag: "hy2-in", Options: &option.Hysteria2InboundOptions{
				ListenOptions: option.ListenOptions{Listen: common.Ptr(badoption.Addr(netip.IPv4Unspecified())), ListenPort: serverPort},
				UpMbps:        100, DownMbps: 100,
				Users: []option.Hysteria2User{{Password: "password"}},
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{
					Enabled: true, ServerName: "example.org", CertificatePath: certPem, KeyPath: keyPem,
				}},
			}},
		},
		Outbounds: []option.Outbound{
			{Type: C.TypeDirect, Tag: "direct"},
			detour,
			{Type: C.TypeHysteria2, Tag: "hy2-out", Options: &option.Hysteria2OutboundOptions{
				DialerOptions: option.DialerOptions{Detour: "detour"},
				ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: serverPort},
				UpMbps:        100, DownMbps: 100, Password: "password",
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
					Enabled: true, ServerName: "example.org", CertificatePath: certPem,
				}},
			}},
		},
		Route: &option.RouteOptions{Rules: []option.Rule{{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{Inbound: []string{"mixed-in"}},
			RuleAction:     option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: "hy2-out"}},
		}}}, Final: "direct"},
	})
	testSuitLargeUDP(t, clientPort, testPort)
}

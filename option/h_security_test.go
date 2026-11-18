package option

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

func TestH_InsecureReason(t *testing.T) {
	verified := OutboundTLSOptionsContainer{TLS: &OutboundTLSOptions{Enabled: true, ServerName: "example.com"}}
	unverified := OutboundTLSOptionsContainer{TLS: &OutboundTLSOptions{Enabled: true, Insecure: true}}
	pinned := OutboundTLSOptionsContainer{TLS: &OutboundTLSOptions{Enabled: true, Insecure: true, CertificatePublicKeySHA256: badoption.Listable[[]byte]{{1}}}}
	reality := OutboundTLSOptionsContainer{TLS: &OutboundTLSOptions{Enabled: true, Insecure: true, Reality: &OutboundRealityOptions{Enabled: true, PublicKey: "k"}}}
	for _, test := range []struct {
		name    string
		options any
		reason  string
	}{
		{"socks", &SOCKSOutboundOptions{}, C.InsecurePlaintext},
		{"http", &HTTPOutboundOptions{}, C.InsecurePlaintext},
		{"https", &HTTPOutboundOptions{OutboundTLSOptionsContainer: verified}, ""},
		{"vless plain", &VLESSOutboundOptions{}, C.InsecurePlaintext},
		{"vless tls", &VLESSOutboundOptions{OutboundTLSOptionsContainer: verified}, ""},
		{"vless insecure", &VLESSOutboundOptions{OutboundTLSOptionsContainer: unverified}, C.InsecureTLSUnverified},
		{"vless pinned", &VLESSOutboundOptions{OutboundTLSOptionsContainer: pinned}, ""},
		{"vless reality", &VLESSOutboundOptions{OutboundTLSOptionsContainer: reality}, ""},
		{"vless encryption", &VLESSOutboundOptions{Encryption: "mlkem768x25519plus.native.0rtt.x"}, ""},
		{"trojan insecure", &TrojanOutboundOptions{OutboundTLSOptionsContainer: unverified}, C.InsecureTLSUnverified},
		{"vmess aes", &VMessOutboundOptions{Security: "aes-128-gcm", OutboundTLSOptionsContainer: unverified}, ""},
		{"vmess none", &VMessOutboundOptions{Security: "none"}, C.InsecureNoCipher},
		{"vmess none tls", &VMessOutboundOptions{Security: "none", OutboundTLSOptionsContainer: verified}, ""},
		{"vmess none insecure", &VMessOutboundOptions{Security: "none", OutboundTLSOptionsContainer: unverified}, C.InsecureTLSUnverified},
		{"shadowsocks", &ShadowsocksOutboundOptions{Method: "2022-blake3-aes-128-gcm"}, ""},
		{"shadowsocks none", &ShadowsocksOutboundOptions{Method: "none"}, C.InsecureNoCipher},
		{"ssr table", &ShadowsocksROutboundOptions{Method: "table"}, C.InsecureWeakCipher},
		{"hysteria2 insecure", &Hysteria2OutboundOptions{OutboundTLSOptionsContainer: unverified}, C.InsecureTLSUnverified},
		{"hysteria2 pinned", &Hysteria2OutboundOptions{OutboundTLSOptionsContainer: pinned}, ""},
		{"tuic", &TUICOutboundOptions{OutboundTLSOptionsContainer: verified}, ""},
		{"masterdns default", &MasterDNSOptions{}, C.InsecureWeakCipher},
		{"masterdns aes", &MasterDNSOptions{Encryption: "aes-256-gcm"}, ""},
		{"masque insecure", &MASQUEOutboundOptions{MASQUEOutboundTLSOptions: MASQUEOutboundTLSOptions{Insecure: true}}, C.InsecureTLSUnverified},
		{"masque pinned", &MASQUEOutboundOptions{MASQUEOutboundTLSOptions: MASQUEOutboundTLSOptions{Insecure: true, CertificatePublicKeySHA256: []string{"ab"}}}, ""},
		{"warp", &WARPEndpointOptions{}, ""},
		{"wireguard", &WireGuardEndpointOptions{}, ""},
		{"ssh", &SSHOutboundOptions{}, ""},
		{"selector", &SelectorOutboundOptions{}, ""},
		{"lazy", &HLazyOptions{Type: C.TypeSOCKS, Options: &SOCKSOutboundOptions{}}, C.InsecurePlaintext},
		{"xray vless tls", &XrayOutboundOptions{XConfig: &map[string]any{
			"protocol":       "vless",
			"streamSettings": map[string]any{"security": "tls", "tlsSettings": map[string]any{"allowInsecure": true}},
		}}, C.InsecureTLSUnverified},
		{"xray vless reality", &XrayOutboundOptions{XConfig: &map[string]any{
			"outbounds": []any{
				map[string]any{"protocol": "freedom"},
				map[string]any{"protocol": "vless", "streamSettings": map[string]any{"security": "reality"}},
			},
		}}, ""},
		{"xray vmess", &XrayOutboundOptions{XConfig: &map[string]any{
			"protocol": "vmess",
			"settings": map[string]any{"vnext": []any{map[string]any{"users": []any{map[string]any{"security": "auto"}}}}},
		}}, ""},
		{"xray socks", &XrayOutboundOptions{XConfig: &map[string]any{"protocol": "socks"}}, C.InsecurePlaintext},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.reason, InsecureReason(test.options))
		})
	}
}

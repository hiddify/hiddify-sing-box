//go:build with_kcp

package box_test

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)


func hOldNew(old bool, oldValue, newValue string) string {
	if old {
		return oldValue
	}
	return newValue
}

func hStartXrayUDP(t *testing.T, binary string, config string) {
	t.Helper()
	hStartXray(t, binary, config, 0)
}

// mKCP against Xray in both directions, plain and with the finalmask mkcp-legacy layers that
// replaced its header and seed.
func TestH_XrayKCP(t *testing.T) {
	binaries := hXrayBinaries(t)
	echoAddress := hStartEcho(t)
	for _, binary := range binaries {
		version := hXrayVersion(t, binary)
		old := strings.HasPrefix(version, "26.3.") // 26.3 names the mkcp masks one by one
		for _, mask := range []struct{ name, xray, singBox string }{
			{"plain", ``, ``},
			{"aes128gcm", hOldNew(old, `, "finalmask": {"udp": [{"type": "mkcp-aes128gcm", "settings": {"password": "hiddify"}}]}`, `, "finalmask": {"udp": [{"type": "mkcp-legacy", "settings": {"value": "hiddify"}}]}`), `, "finalmask": {"udp": [{"type": "mkcp-legacy", "settings": {"value": "hiddify"}}]}`},
			{"wechat", hOldNew(old, `, "finalmask": {"udp": [{"type": "header-wechat"}]}`, `, "finalmask": {"udp": [{"type": "mkcp-legacy", "settings": {"header": "wechat"}}]}`), `, "finalmask": {"udp": [{"type": "mkcp-legacy", "settings": {"header": "wechat"}}]}`},
		} {
			t.Run(version+"/sing-box-client/"+mask.name, func(t *testing.T) {
				xrayPort := hFreeUDPPort(t)
				hStartXrayUDP(t, binary, `{
					"log": {"loglevel": "warning"},
					"inbounds": [{"listen": "127.0.0.1", "port": `+strconv.Itoa(xrayPort)+`, "protocol": "vless",
						"settings": {"clients": [{"id": "`+hInteropUUID+`"}], "decryption": "none"},
						"streamSettings": {"network": "mkcp"`+mask.xray+`}}],
					"outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}]
				}`)
				mixedPort := hFreeTCPPort(t)
				hStartInteropBox(t, `{
					"log": {"disabled": true},
					"inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(mixedPort)+`}],
					"outbounds": [{"type": "vless", "server": "127.0.0.1", "server_port": `+strconv.Itoa(xrayPort)+`,
						"uuid": "`+hInteropUUID+`", "transport": {"type": "mkcp"}`+mask.singBox+`}]
				}`, nil)
				hEchoThroughSOCKS(t, mixedPort, echoAddress)
			})
		}
		t.Run(version+"/xray-client/plain", func(t *testing.T) {
			vlessPort := hFreeUDPPort(t)
			hStartInteropBox(t, `{
				"log": {"disabled": true},
				"inbounds": [{"type": "vless", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(vlessPort)+`,
					"users": [{"uuid": "`+hInteropUUID+`"}], "transport": {"type": "kcp"}}],
				"outbounds": [{"type": "direct"}]
			}`, nil)
			socksPort := hFreeTCPPort(t)
			hStartXray(t, binary, `{
				"log": {"loglevel": "warning"},
				"inbounds": [{"listen": "127.0.0.1", "port": `+strconv.Itoa(socksPort)+`, "protocol": "socks", "settings": {"udp": false}}],
				"outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": `+strconv.Itoa(vlessPort)+`,
					"users": [{"id": "`+hInteropUUID+`", "encryption": "none"}]}]}, "streamSettings": {"network": "kcp"}}]
			}`, socksPort)
			hEchoThroughSOCKS(t, socksPort, echoAddress)
		})
	}
}

// sing-box to sing-box over mKCP, with TLS inside it
func TestH_KCPWithTLS(t *testing.T) {
	certPEM, keyPEM := hSelfSignedPEM(t)
	echoAddress := hStartEcho(t)
	vlessPort := hFreeUDPPort(t)
	mixedPort := hFreeTCPPort(t)
	hStartInteropBox(t, `{
		"log": {"disabled": true},
		"inbounds": [
			{"type": "vless", "tag": "vless-in", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(vlessPort)+`, "users": [{"uuid": "`+hInteropUUID+`"}],
				"transport": {"type": "mkcp"}, "tls": {"enabled": true, "server_name": "example.com", "certificate": `+hJSONString(certPEM)+`, "key": `+hJSONString(keyPEM)+`}},
			{"type": "mixed", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(mixedPort)+`}
		],
		"outbounds": [
			{"type": "vless", "tag": "kcp", "server": "127.0.0.1", "server_port": `+strconv.Itoa(vlessPort)+`, "uuid": "`+hInteropUUID+`",
				"transport": {"type": "kcp"}, "tls": {"enabled": true, "server_name": "example.com", "insecure": true}},
			{"type": "direct", "tag": "direct"}
		],
		"route": {"rules": [{"inbound": "vless-in", "outbound": "direct"}], "final": "kcp"}
	}`, nil)
	hEchoThroughSOCKS(t, mixedPort, echoAddress)
}

func hJSONString(value string) string {
	content, _ := json.Marshal(value)
	return string(content)
}

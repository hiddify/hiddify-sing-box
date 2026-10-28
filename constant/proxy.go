package constant

import (
	"strings"
	"time"
)

const (
	TypeTun                = "tun"
	TypeRedirect           = "redirect"
	TypeTProxy             = "tproxy"
	TypeDirect             = "direct"
	TypeBridge             = "bridge"
	TypeBlock              = "block"
	TypeDNS                = "dns"
	TypeSOCKS              = "socks"
	TypeHTTP               = "http"
	TypeMixed              = "mixed"
	TypeShadowsocks        = "shadowsocks"
	TypeSnell              = "snell"
	TypeVMess              = "vmess"
	TypeTrojan             = "trojan"
	TypeNaive              = "naive"
	TypeWireGuard          = "wireguard"
	TypeLegacyWireGuard    = "wireguard_legacy" //H
	TypeHysteria           = "hysteria"
	TypeTor                = "tor"
	TypeSSH                = "ssh"
	TypeShadowTLS          = "shadowtls"
	TypeAnyTLS             = "anytls"
	TypeShadowsocksR       = "shadowsocksr"
	TypeVLESS              = "vless"
	TypeTUIC               = "tuic"
	TypeHysteria2          = "hysteria2"
	TypeOpenConnect        = "openconnect"
	TypeOpenVPNClient      = "openvpn-client"
	TypeOpenVPNServer      = "openvpn-server"
	TypeMASQUEClient       = "masque-client"
	TypeMASQUEServer       = "masque-server"
	TypeTailscale          = "tailscale"
	TypeTailcat            = "tailcat"
	TypeCloudflared        = "cloudflared"
	TypeDERP               = "derp"
	TypeResolved           = "resolved"
	TypeSSMAPI             = "ssm-api"
	TypeAPI                = "api"
	TypeCCM                = "ccm"
	TypeOCM                = "ocm"
	TypeOOMKiller          = "oom-killer"
	TypeUSBIPServer        = "usbip-server"
	TypeUSBIPClient        = "usbip-client"
	TypeHysteriaRealm      = "hysteria-realm"
	TypeACME               = "acme"
	TypeCloudflareOriginCA = "cloudflare-origin-ca"
	TypeWARP               = "warp"
	TypeMieru              = "mieru"
	TypeMASQUE             = "masque"
	TypePsiphon            = "psiphon"
	TypeTunnelClient       = "tunnel_client"
	TypeTunnelServer       = "tunnel_server"

	TypeHInvalidConfig = "hinvalid"       //H
	TypeXray           = "xray"           //H
	TypeCustom         = "custom"         //H
	TypeAwg            = "awg"            //H
	TypeBalancer       = "balancer"       //H
	TypeFallback       = "fallback"       //H
	TypeSudoku         = "sudoku"         //H
	TypeBond           = "bond"           //H
	TypeCall           = "call"           //H
	TypeDNSTT          = "dnstt"          //H
	TypeGooseRelay     = "gooserelay"     //H
	TypeSmartDNSPool   = "smart_dns_pool" //H — local recursive-resolver pool with AIMD throttling + recovery probing (github.com/hiddify/hmrd_multi_resolver_dns)
	TypeTrustTunnel    = "trusttunnel"
)

const (
	TypeSelector = "selector"
	TypeURLTest  = "urltest"
)

// Display names of a warp endpoint, and of a masque outbound to WARP, by tunnel. //H
const (
	DisplayWARPWireGuard = "WARP · WG"
	DisplayWARPAWG       = "WARP · AWG"
	DisplayWARPMASQUE    = "WARP · MASQUE"
)

// HourglassFlip are the frames of the connecting mark: an hourglass that flips each second. //H
var HourglassFlip = []string{"⏳", "⌛"}

const connectingText = "Connecting..."

// DisplayConnecting is added to a display type while the outbound is not connected; the
// hourglass flips each second, so a display that refreshes shows it turning. //H
func DisplayConnecting() string {
	return connectingMark(HourglassFlip[time.Now().Unix()%int64(len(HourglassFlip))])
}

func connectingMark(frame string) string {
	return " " + frame + " " + connectingText
}

// SplitConnecting separates a display type from its connecting mark, which is always last;
// mark is empty when it has none. //H
func SplitConnecting(display string) (base string, mark string) {
	for _, frame := range HourglassFlip {
		if suffix := connectingMark(frame); strings.HasSuffix(display, suffix) {
			return strings.TrimSuffix(display, suffix), strings.TrimSpace(suffix)
		}
	}
	return display, ""
}

func ProxyDisplayName(proxyType string) string {
	switch proxyType {
	case TypeTun:
		return "TUN"
	case TypeRedirect:
		return "Redirect"
	case TypeTProxy:
		return "TProxy"
	case TypeDirect:
		return "Direct"
	case TypeBridge:
		return "Bridge"
	case TypeBlock:
		return "Block"
	case TypeDNS:
		return "DNS"
	case TypeSOCKS:
		return "SOCKS"
	case TypeHTTP:
		return "HTTP"
	case TypeMixed:
		return "Mixed"
	case TypeShadowsocks:
		return "Shadowsocks"
	case TypeSnell:
		return "Snell"
	case TypeVMess:
		return "VMess"
	case TypeTrojan:
		return "Trojan"
	case TypeNaive:
		return "Naive"
	case TypeWireGuard:
		return "WireGuard"
	case TypeHysteria:
		return "Hysteria"
	case TypeTor:
		return "Tor"
	case TypeSSH:
		return "SSH"
	case TypeShadowTLS:
		return "ShadowTLS"
	case TypeShadowsocksR:
		return "ShadowsocksR"
	case TypeVLESS:
		return "VLESS"
	case TypeTUIC:
		return "TUIC"
	case TypeHysteria2:
		return "Hysteria2"
	case TypeAnyTLS:
		return "AnyTLS"
	case TypeOpenConnect:
		return "OpenConnect"
	case TypeOpenVPNClient:
		return "OpenVPN Client"
	case TypeOpenVPNServer:
		return "OpenVPN Server"
	case TypeMASQUEClient:
		return "MASQUE Client"
	case TypeMASQUEServer:
		return "MASQUE Server"
	case TypeTailscale:
		return "Tailscale"
	case TypeTailcat:
		return "Tailcat"
	case TypeCloudflared:
		return "Cloudflared"
	case TypeWARP:
		return "WARP"
	case TypeMieru:
		return "Mieru"
	case TypeMASQUE:
		return "MASQUE"
	case TypePsiphon:
		return "Psiphon"
	case TypeHInvalidConfig:
		return "Invalid"
	case TypeXray:
		return "xray"
	case TypeCustom:
		return "custom"
	case TypeTunnelClient:
		return "Tunnel Client"
	case TypeTunnelServer:
		return "Tunnel Server"
	case TypeAwg:
		return "Awg"
	case TypeBalancer:
		return "Balancer"
	case TypeFallback: //H
		return "Fallback" //H
	case TypeSudoku: //H
		return "Sudoku" //H
	case TypeBond: //H
		return "Bond" //H
	case TypeCall: //H
		return "Call" //H
	case TypeDNSTT:
		return "DNSTT"
	case TypeGooseRelay:
		return "GooseRelay"
	case TypeTrustTunnel:
		return "TrustTunnel"
	case TypeSelector:
		return "Selector"
	case TypeURLTest:
		return "URLTest"
	default:
		return "Unknown"
	}
}

const DefaultBrowserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"

const URLTestModeFailover = "failover" //H: keep the selected member until it fails

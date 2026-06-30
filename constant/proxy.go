package constant

const (
	TypeTun                = "tun"
	TypeRedirect           = "redirect"
	TypeTProxy             = "tproxy"
	TypeDirect             = "direct"
	TypeBlock              = "block"
	TypeDNS                = "dns"
	TypeSOCKS              = "socks"
	TypeHTTP               = "http"
	TypeMixed              = "mixed"
	TypeShadowsocks        = "shadowsocks"
	TypeVMess              = "vmess"
	TypeTrojan             = "trojan"
	TypeNaive              = "naive"
	TypeWireGuard          = "wireguard"
	TypeWARP               = "warp"
	TypeHysteria           = "hysteria"
	TypeTor                = "tor"
	TypeSSH                = "ssh"
	TypeShadowTLS          = "shadowtls"
	TypeMieru              = "mieru"
	TypeAnyTLS             = "anytls"
	TypeSnell              = "snell"
	TypeMASQUE             = "masque"
	TypeShadowsocksR       = "shadowsocksr"
	TypeVLESS              = "vless"
	TypeTUIC               = "tuic"
	TypeHysteria2          = "hysteria2"
	TypeHysteriaRealm      = "hysteria-realm"
	TypePsiphon            = "psiphon"
	TypeTunnelClient       = "tunnel_client"
	TypeTunnelServer       = "tunnel_server"
	TypeTailscale          = "tailscale"
	TypeCloudflared        = "cloudflared"
	TypeDERP               = "derp"
	TypeResolved           = "resolved"
	TypeSSMAPI             = "ssm-api"
	TypeCCM                = "ccm"
	TypeOCM                = "ocm"
	TypeOOMKiller          = "oom-killer"
	TypeACME               = "acme"
	TypeCloudflareOriginCA = "cloudflare-origin-ca"

	TypeHInvalidConfig = "hinvalid" //H
	TypeXray           = "xray"     //H
	TypeCustom         = "custom"   //H
	TypeAwg            = "awg"      //H
	TypeBalancer       = "balancer" //H
	TypeDNSTT          = "dnstt"    //H
  TypeGooseRelay     = "gooserelay" //H
	TypeFirebaseTunnel = "firebasetunnel" //H
	TypeSmartDNSPool   = "smart_dns_pool" //H — local recursive-resolver pool with AIMD throttling + recovery probing (github.com/hiddify/hmrd_multi_resolver_dns)
)

const (
	TypeSelector = "selector"
	TypeURLTest  = "urltest"
)

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
	case TypeVMess:
		return "VMess"
	case TypeTrojan:
		return "Trojan"
	case TypeNaive:
		return "Naive"
	case TypeWireGuard:
		return "WireGuard"
	case TypeWARP:
		return "WARP"
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
	case TypeMieru:
		return "Mieru"
	case TypeAnyTLS:
		return "AnyTLS"
	case TypeSnell:
		return "Snell"
	case TypeMASQUE:
		return "MASQUE"
	case TypePsiphon:
		return "Psiphon"
	case TypeTailscale:
		return "Tailscale"
	case TypeCloudflared:
		return "Cloudflared"
	case TypeSelector:
		return "Selector"
	case TypeURLTest:
		return "URLTest"
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
	case TypeDNSTT:
		return "DNSTT"
	case TypeGooseRelay:
		return "GooseRelay"
	case TypeFirebaseTunnel:
		return "Firebase Tunnel"
	default:
		return "Unknown"
	}
}

const DefaultBrowserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"

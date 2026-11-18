package option

import (
	"strings"

	C "github.com/sagernet/sing-box/constant"
)

// InsecureReason says why an outbound or an endpoint with these options can be read or changed on
// the way to its server, as one of the C.Insecure* reasons, or "" when it cannot, or when it is not
// a proxy (direct, block, a group). //H
//
// A proxy is secure when something encrypts its traffic and checks who the server is: its own
// encryption (Shadowsocks, VMess, WireGuard, SSH, ...), or TLS that verifies the server's
// certificate, or TLS with insecure on but the certificate pinned (certificate_sha256,
// certificate_public_key_sha256), or REALITY.
func InsecureReason(options any) string {
	switch o := options.(type) {
	case *HLazyOptions: // a lazy one is as secure as the real one it stands for
		if o.HeldOptions != nil { // the config's own options
			return InsecureReason(o.HeldOptions)
		}
		return InsecureReason(o.Options)
	case *SOCKSOutboundOptions:
		return C.InsecurePlaintext
	case *HTTPOutboundOptions:
		return tlsInsecureReason(o.TLS)
	case *ShadowsocksOutboundOptions:
		return shadowsocksInsecureReason(o.Method)
	case *ShadowsocksROutboundOptions:
		return shadowsocksInsecureReason(o.Method)
	case *VMessOutboundOptions:
		switch o.Security {
		case "none", "zero":
			return tlsOrPlainInsecureReason(o.TLS, C.InsecureNoCipher)
		}
		return ""
	case *VLESSOutboundOptions:
		if vlessEncrypted(o.Encryption) {
			return ""
		}
		return tlsInsecureReason(o.TLS)
	case *TrojanOutboundOptions:
		return tlsInsecureReason(o.TLS)
	case *AnyTLSOutboundOptions:
		return tlsInsecureReason(o.TLS)
	case *NaiveOutboundOptions:
		return tlsInsecureReason(o.TLS)
	case *HysteriaOutboundOptions:
		return tlsInsecureReason(o.TLS)
	case *Hysteria2OutboundOptions:
		return tlsInsecureReason(o.TLS)
	case *TUICOutboundOptions:
		return tlsInsecureReason(o.TLS)
	case *TrustTunnelOutboundOptions:
		return tlsInsecureReason(o.TLS)
	case *MASQUEClientEndpointOptions:
		return tlsInsecureReason(o.TLS)
	case *MASQUEOutboundOptions:
		return masqueInsecureReason(o.MASQUEOutboundTLSOptions)
	case *WARPEndpointOptions:
		if o.MASQUE != nil {
			return masqueInsecureReason(o.MASQUE.TLS)
		}
		return "" // WireGuard
	case *SudokuOutboundOptions:
		if strings.EqualFold(o.AEADMethod, "none") {
			if o.HTTPMask != nil && o.HTTPMask.Enabled && o.HTTPMask.TLS != nil && o.HTTPMask.TLS.Enabled {
				return tlsInsecureReason(o.HTTPMask.TLS)
			}
			return C.InsecureNoCipher
		}
		return ""
	case *MasterDNSOptions:
		switch strings.ToLower(strings.TrimSpace(o.Encryption)) {
		case "none", "0":
			return C.InsecureNoCipher
		case "", "xor", "1": // xor, the default, hides the data but does not encrypt it
			return C.InsecureWeakCipher
		}
		return ""
	case *XrayOutboundOptions:
		if o.XConfig != nil {
			return xrayInsecureReason(*o.XConfig)
		}
		if o.DeprecatedXrayOutboundJson != nil {
			return xrayInsecureReason(*o.DeprecatedXrayOutboundJson)
		}
		return ""
	}
	// encrypted by the protocol itself (WireGuard, AmneziaWG, SSH, Snell, Mieru, Tor, Psiphon,
	// dnstt, Soar, GooseRelay, Tailscale, OpenVPN, ...), a transport whose inner proxy decides
	// (ShadowTLS), or not a proxy at all
	return ""
}

// tlsInsecureReason is the reason of a proxy that only TLS encrypts.
func tlsInsecureReason(tls *OutboundTLSOptions) string {
	if tls == nil || !tls.Enabled {
		return C.InsecurePlaintext
	}
	if tls.Reality != nil && tls.Reality.Enabled {
		return "" // the server is checked by its REALITY public key
	}
	if tls.Insecure && len(tls.CertificateSHA256) == 0 && len(tls.CertificatePublicKeySHA256) == 0 {
		return C.InsecureTLSUnverified
	}
	return ""
}

// tlsOrPlainInsecureReason is tlsInsecureReason, with plain as the reason when there is no TLS.
func tlsOrPlainInsecureReason(tls *OutboundTLSOptions, plain string) string {
	reason := tlsInsecureReason(tls)
	if reason == C.InsecurePlaintext {
		return plain
	}
	return reason
}

func shadowsocksInsecureReason(method string) string {
	switch strings.ToLower(method) {
	case "", "none", "plain", "dummy":
		return C.InsecureNoCipher
	case "table", "rc4":
		return C.InsecureWeakCipher
	}
	return ""
}

func vlessEncrypted(encryption string) bool {
	encryption = strings.TrimSpace(encryption)
	return encryption != "" && !strings.EqualFold(encryption, "none")
}

func masqueInsecureReason(tls MASQUEOutboundTLSOptions) string {
	if tls.Insecure && len(tls.CertificatePublicKeySHA256) == 0 {
		return C.InsecureTLSUnverified
	}
	return ""
}

// xrayInsecureReason reads an Xray config: a whole one with outbounds, whose first proxy is the
// one used, or just that outbound.
func xrayInsecureReason(config map[string]any) string {
	outbound := config
	if outbounds, ok := config["outbounds"].([]any); ok {
		outbound = nil
		for _, item := range outbounds {
			candidate, _ := item.(map[string]any)
			switch protocol, _ := candidate["protocol"].(string); protocol {
			case "", "freedom", "blackhole", "dns", "loopback":
				continue
			}
			outbound = candidate
			break
		}
		if outbound == nil {
			return ""
		}
	}
	protocol, _ := outbound["protocol"].(string)
	settings, _ := outbound["settings"].(map[string]any)
	streamSettings, _ := outbound["streamSettings"].(map[string]any)
	plain := C.InsecurePlaintext
	switch strings.ToLower(protocol) {
	case "vless":
		if vlessEncrypted(xrayUserField(settings, "encryption")) {
			return ""
		}
	case "trojan", "socks", "http":
	case "vmess":
		switch strings.ToLower(xrayUserField(settings, "security")) {
		case "none", "zero":
			plain = C.InsecureNoCipher
		default:
			return ""
		}
	case "shadowsocks":
		method, _ := settings["method"].(string)
		if method == "" {
			if servers, ok := settings["servers"].([]any); ok && len(servers) > 0 {
				server, _ := servers[0].(map[string]any)
				method, _ = server["method"].(string)
			}
		}
		if reason := shadowsocksInsecureReason(method); reason != "" {
			plain = reason
		} else {
			return ""
		}
	default:
		return "" // wireguard, hysteria, ...: encrypted by the protocol
	}
	security, _ := streamSettings["security"].(string)
	switch strings.ToLower(security) {
	case "reality":
		return ""
	case "tls":
		tlsSettings, _ := streamSettings["tlsSettings"].(map[string]any)
		insecure, _ := tlsSettings["allowInsecure"].(bool)
		if !insecure {
			return ""
		}
		for _, pin := range []string{"pinnedPeerCertSha256", "pinnedPeerCertificateChainSha256", "pinnedPeerCertificatePublicKeySha256", "pinnedPeerPublicKeySha256"} {
			if value, present := tlsSettings[pin]; present && value != nil && value != "" {
				if list, isList := value.([]any); !isList || len(list) > 0 {
					return ""
				}
			}
		}
		return C.InsecureTLSUnverified
	}
	return plain
}

// xrayUserField is a field of the first user of an Xray vless or vmess outbound: in settings
// itself (the flat form) or in settings.vnext[0].users[0].
func xrayUserField(settings map[string]any, field string) string {
	if value, ok := settings[field].(string); ok {
		return value
	}
	vnext, _ := settings["vnext"].([]any)
	if len(vnext) == 0 {
		return ""
	}
	server, _ := vnext[0].(map[string]any)
	users, _ := server["users"].([]any)
	if len(users) == 0 {
		return ""
	}
	user, _ := users[0].(map[string]any)
	value, _ := user[field].(string)
	return value
}

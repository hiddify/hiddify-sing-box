package xhttp

import (
	"github.com/sagernet/sing-box/common/tls"
)

// hDefaultALPN gives a TLS client without ALPN the ALPN Xray's client uses, h2 and http/1.1, so
// the client speaks HTTP/2 as Xray's does. Before, it spoke HTTP/1.1 while a uTLS fingerprint
// still offered the browser's h2 in its hello: a server that picked h2 (Xray, Cloudflare) got an
// HTTP/1.1 request and closed the connection (hiddify-app#2542). REALITY keeps its own ALPN. The
// outbound's TLS config is cloned, not changed.
func hDefaultALPN(tlsConfig tls.Config) tls.Config {
	if tlsConfig == nil || tls.IsReality(tlsConfig) || len(tlsConfig.NextProtos()) > 0 {
		return tlsConfig
	}
	tlsConfig = tlsConfig.Clone()
	tlsConfig.SetNextProtos([]string{"h2", "http/1.1"})
	return tlsConfig
}

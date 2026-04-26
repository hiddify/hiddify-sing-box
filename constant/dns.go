package constant

const (
	DefaultDNSTTL = 600
)

type DomainStrategy = uint8

const (
	DomainStrategyAsIS DomainStrategy = iota
	DomainStrategyPreferIPv4
	DomainStrategyPreferIPv6
	DomainStrategyIPv4Only
	DomainStrategyIPv6Only
)

const (
	DNSTypeLegacy      = "legacy"
	DNSTypeLegacyRcode = "legacy_rcode"
	DNSTypeUDP         = "udp"
	DNSTypeTCP         = "tcp"
	DNSTypeTLS         = "tls"
	DNSTypeHTTPS       = "https"
	DNSTypeQUIC        = "quic"
	DNSTypeHTTP3       = "h3"
	DNSTypeLocal       = "local"
	DNSTypeHosts       = "hosts"
	DNSTypeFakeIP      = "fakeip"
	DNSTypeDHCP        = "dhcp"
	DNSTypeTailscale   = "tailscale"
	DNSTypeSDNS        = "sdns"

	DNSTypeMulti = "multi" //H
	DNSTypeHMRD  = "hmrd"  //H — smart multi-resolver (github.com/hiddify/hmrd_multi_resolver_dns)
)

const (
	DNSProviderAliDNS     = "alidns"
	DNSProviderCloudflare = "cloudflare"
	DNSProviderACMEDNS    = "acmedns"
)

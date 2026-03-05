package option

type DnsttOptions struct {
	DialerOptions
	PublicKey         string             `json:"publicKey"`
	Domain            string             `json:"domain"`
	Resolvers         []string           `json:"resolvers"`
	TunnelPerResolver int                `json:"tunnel_per_resolver,omitempty"`
	UDPOverTCP        *UDPOverTCPOptions `json:"udp_over_tcp,omitempty"`
	Network           NetworkList        `json:"network,omitempty"`
}

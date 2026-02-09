package option

type DnsttOptions struct {
	PublicKey string   `json:"publicKey"`
	Domain    string   `json:"domain"`
	Resolvers []string `json:"resolvers"`
}

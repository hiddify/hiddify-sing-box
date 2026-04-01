package option

import (
	"github.com/sagernet/sing/common/json/badoption"
)

type DnsttOptions struct {
	DialerOptions

	PublicKey         string `json:"pubkey,omitempty"`
	Domain            string `json:"domain,omitempty"`
	PreTestDomain     string `json:"pretest-domain,omitempty"`
	PreTestRecordType string `json:"pretest-record-type,omitempty"`

	RecordType        string `json:"record-type,omitempty"`
	UTLSClientHelloID string `json:"utls,omitempty"`

	Resolvers                   []string `json:"resolvers,omitempty"`
	DeprecatedTunnelPerResolver int      `json:"tunnel-per-resolver,omitempty"`
	SingleResolver              bool     `json:"single-resolver,omitempty"`

	DnsttCompat  bool     `json:"dnstt-compat,omitempty"`
	ClientIDSize *int     `json:"clientid-size,omitempty"`
	MaxQnameLen  *int     `json:"max-qname-len,omitempty"`
	MaxNumLabels *int     `json:"max-num-labels,omitempty"`
	RPS          *float64 `json:"rps,omitempty"`

	MTU *int `json:"mtu,omitempty"`

	IdleTimeout          *badoption.Duration `json:"idle-timeout,omitempty"`
	KeepAlive            *badoption.Duration `json:"keepalive,omitempty"`
	OpenStreamTimeout    *badoption.Duration `json:"open-stream-timeout,omitempty"`
	MaxStreams           *int                `json:"max-streams,omitempty"`
	ReconnectMinDelay    *badoption.Duration `json:"reconnect-min,omitempty"`
	ReconnectMaxDelay    *badoption.Duration `json:"reconnect-max,omitempty"`
	SessionCheckInterval *badoption.Duration `json:"session-check-interval,omitempty"`
	HandshakeTimeout     *badoption.Duration `json:"handshake-timeout,omitempty"`

	UdpAcceptErrors bool                `json:"udp-accept-errors,omitempty"`
	UdpSharedSocket bool                `json:"udp-shared-socket,omitempty"`
	UdpTimeout      *badoption.Duration `json:"udp-timeout,omitempty"`
	UdpWorkers      *int                `json:"udp-workers,omitempty"`
}

package option

import (
	"net/netip"
	"strconv"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"

	"github.com/sagernet/sing/common/json/badoption"
)

type AwgEndpointOptions struct {
	UseIntegratedTun bool                             `json:"useIntegratedTun"`
	PrivateKey       string                           `json:"private_key"`
	Address          badoption.Listable[netip.Prefix] `json:"address"`
	MTU              uint32                           `json:"mtu,omitempty"`
	ListenPort       uint16                           `json:"listen_port,omitempty"`
	Awg              AwgOptions                       `json:"awg,omitempty"`
	Peers            []AwgPeerOptions                 `json:"peers,omitempty"`
	DialerOptions
}

type AwgOptions struct {
	Jc   int    `json:"jc,omitempty"`
	Jmin int    `json:"jmin,omitempty"`
	Jmax int    `json:"jmax,omitempty"`
	S1   int    `json:"s1,omitempty"`
	S2   int    `json:"s2,omitempty"`
	S3   int    `json:"s3,omitempty"`
	S4   int    `json:"s4,omitempty"`
	H1   string `json:"h1,omitempty"`
	H2   string `json:"h2,omitempty"`
	H3   string `json:"h3,omitempty"`
	H4   string `json:"h4,omitempty"`
	I1   string `json:"i1,omitempty"`
	I2   string `json:"i2,omitempty"`
	I3   string `json:"i3,omitempty"`
	I4   string `json:"i4,omitempty"`
	I5   string `json:"i5,omitempty"`

	// AmneziaWG 3.x. The range values are seconds (counts for max_handshake_attempts, bytes for
	// content_padding_addition), a number or "min-max".
	HeaderProtectionKey    string   `json:"header_protection_key,omitempty"` // 64 hex digits
	ContentPaddingAddition AwgRange `json:"content_padding_addition,omitempty"`
	RekeyAfterTime         AwgRange `json:"rekey_after_time,omitempty"`
	RekeyTimeout           AwgRange `json:"rekey_timeout,omitempty"`
	RejectAfterTime        AwgRange `json:"reject_after_time,omitempty"`
	KeepaliveTimeout       AwgRange `json:"keepalive_timeout,omitempty"`
	MaxHandshakeAttempts   AwgRange `json:"max_handshake_attempts,omitempty"`
	RandomTrailers         bool     `json:"random_trailers,omitempty"`
	DisableCookies         bool     `json:"disable_cookies,omitempty"`

	// Masquerade, as in sing-box-lx: i1 becomes a decoy of protocol ip ("quic") for domain id,
	// built afresh before every handshake. ib names the client profile. Not with i1.
	IP string `json:"ip,omitempty"`
	ID string `json:"id,omitempty"`
	IB string `json:"ib,omitempty"`
}

// AwgRange is an AmneziaWG range, written as a number or as "min-max".
type AwgRange string

func (r *AwgRange) UnmarshalJSON(content []byte) error {
	var number uint32
	if err := json.Unmarshal(content, &number); err == nil {
		*r = AwgRange(strconv.FormatUint(uint64(number), 10))
		return nil
	}
	var value string
	if err := json.Unmarshal(content, &value); err != nil {
		return E.New("an AmneziaWG range is a number or \"min-max\"")
	}
	*r = AwgRange(value)
	return nil
}

func (o *AwgOptions) IsAvailble() bool {
	if o == nil {
		return false
	}
	return o.Jc != 0 || o.Jmin != 0 || o.Jmax != 0 || o.S1 != 0 || o.S2 != 0 || o.S3 != 0 || o.S4 != 0 || o.H1 != "" || o.H2 != "" || o.H3 != "" || o.H4 != "" || o.I1 != "" || o.I2 != "" || o.I3 != "" || o.I4 != "" || o.I5 != "" ||
		o.HeaderProtectionKey != "" || o.ContentPaddingAddition != "" || o.RekeyAfterTime != "" || o.RekeyTimeout != "" || o.RejectAfterTime != "" ||
		o.KeepaliveTimeout != "" || o.MaxHandshakeAttempts != "" || o.RandomTrailers || o.DisableCookies || o.IP != "" || o.ID != "" || o.IB != ""
}

type AwgPeerOptions struct {
	// H: connections from this peer are accounted to this user (metadata.User)
	Username                    string                           `json:"name,omitempty"`
	Address                     string                           `json:"address,omitempty"`
	Port                        uint16                           `json:"port,omitempty"`
	PublicKey                   string                           `json:"public_key,omitempty"`
	PresharedKey                string                           `json:"preshared_key,omitempty"`
	AllowedIPs                  badoption.Listable[netip.Prefix] `json:"allowed_ips,omitempty"`
	PersistentKeepaliveInterval uint16                           `json:"persistent_keepalive_interval,omitempty"`
}

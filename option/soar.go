package option

import (
	"github.com/sagernet/sing/common/json/badoption"
)

// SoarOptions configure the soar outbound: a Soar client (github.com/getlantern/soar) that
// carries TCP connections inside DNS queries, through recursive resolvers, to a Soar server that
// is the authority for the tunnel zone. Every field that is unset keeps the Soar client's default.
type SoarOptions struct {
	DialerOptions

	// Domain is the tunnel zone delegated to the server (soar-server -zone).
	Domain string `json:"domain,omitempty"`
	// PublicKey is the server's Ed25519 public key, as soar-server pubkey prints it (base64;
	// base64url and hex are read too).
	PublicKey string `json:"public_key,omitempty"`
	// Resolvers are the recursive resolvers to send the queries through: "8.8.8.8",
	// "1.1.1.1:5353" or "auto". "auto", or no resolvers at all, turns on Soar's own resolver
	// discovery, steered by smart_pool.discovery (ResolverDiscoveryOptions). With
	// the smart pool the others may also be "tcp://", "dot://host:853" or
	// "https://host/dns-query".
	Resolvers badoption.Listable[string] `json:"resolvers,omitempty"`

	// SmartPool sends the queries for the resolvers written in Resolvers through the outbound's
	// own resolver pool (SmartPoolOptions), and is on unless set to false: the Soar client sees
	// the pool as one resolver. Off, the client uses each resolver as a path of its own.
	// Resolvers found by Soar's discovery are paths of their own either way; its settings are in
	// smart_pool.discovery, which applies with the pool off too ({"enabled": false, "discovery": ...}).
	SmartPool *SmartPoolOptions `json:"smart_pool,omitempty"`
	// PreTestDomain and PreTestRecordType are the plain query sent to each resolver before it
	// joins the pool. Defaults: www.google.com, a.
	PreTestDomain     string `json:"pretest_domain,omitempty"`
	PreTestRecordType string `json:"pretest_record_type,omitempty"`

	// TCP is the use of DNS over TCP to the resolvers: auto (default: for a resolver whose UDP
	// never answers), on, only or off. With the smart pool alone it is off: the pool reaches the
	// resolvers itself.
	TCP string `json:"tcp,omitempty"`
	// SafeQName is the query name length every resolver starts at (default 101, the most some
	// networks pass); MaxQName the longest it probes up to (default 253).
	SafeQName int `json:"safe_qname,omitempty"`
	MaxQName  int `json:"max_qname,omitempty"`
	// MaxAnswer caps the DNS answer size, in bytes, probed up to (default 1232).
	MaxAnswer int `json:"max_answer,omitempty"`
	// Hold is how long the server may hold an idle query (default 500ms).
	Hold badoption.Duration `json:"hold,omitempty"`
	// MaxInflight caps the queries outstanding over all resolvers (default 128); MaxPathWindow
	// over one resolver (default 32; with the smart pool alone, MaxInflight, since the pool is
	// one).
	MaxInflight   int `json:"max_inflight,omitempty"`
	MaxPathWindow int `json:"max_path_window,omitempty"`
	// MaxStreams caps the connections open at once (default 64, at most 256).
	MaxStreams int `json:"max_streams,omitempty"`
	// StreamWindow and SendBuffer are each connection's receive window and send buffer, in
	// bytes (defaults 256 KiB and 64 KiB).
	StreamWindow int `json:"stream_window,omitempty"`
	SendBuffer   int `json:"send_buffer,omitempty"`
	// SessionIdle ends a session without connections after this long, below the server's idle
	// timeout (default 90s).
	SessionIdle badoption.Duration `json:"session_idle,omitempty"`
	// ConnectTimeout is how long a connection may wait for the session (default 90s).
	ConnectTimeout badoption.Duration `json:"connect_timeout,omitempty"`
}

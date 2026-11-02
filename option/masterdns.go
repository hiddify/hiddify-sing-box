package option

import (
	"github.com/sagernet/sing/common/json/badoption"
)

// MasterDNSOptions configure the masterdns outbound: a MasterDnsVPN client that carries TCP
// connections inside DNS queries to a MasterDnsVPN server, through public resolvers. Every field
// that is unset keeps the MasterDnsVPN client's default, documented in
// docs/hiddify/features/protocols/masterdns.en.md.
type MasterDNSOptions struct {
	DialerOptions

	// Domains are the tunnel domains the server is the authority for (the server's DOMAIN). At
	// least one; all must belong to the same server.
	Domains badoption.Listable[string] `json:"domains,omitempty"`
	// Resolvers are plain DNS resolvers to send the queries through: "8.8.8.8", "1.1.1.1:5353",
	// "10.0.0.0/30", "10.0.0.0/30:5353" or "[2001:db8::1]:53". At least one.
	Resolvers badoption.Listable[string] `json:"resolvers,omitempty"`
	// Encryption is the server's DATA_ENCRYPTION_METHOD: none, xor (default), chacha20,
	// aes-128-gcm, aes-192-gcm or aes-256-gcm, or its number 0 to 5.
	Encryption string `json:"encryption,omitempty"`
	// Key is the server's encryption key (encrypt_key.txt). Required unless encryption is none.
	Key string `json:"key,omitempty"`
	// Mode is the server's PROTOCOL_TYPE: socks5 (default; the server connects each connection to
	// its destination) or tcp (the server forwards every connection to its fixed target, and the
	// destination is ignored).
	Mode string `json:"mode,omitempty"`

	// SmartPool sends the queries through the outbound's own resolver pool (SmartPoolOptions, the
	// same as dnstt's) instead of giving the resolvers to the MasterDnsVPN client one by one: each
	// resolver is probed with a plain query first, the pool spreads the queries over the ones that
	// answer, slows down for one that rate-limits and skips one that stops answering. With it,
	// resolvers may also be "dot://host:853", "https://host/dns-query" or "auto" (the built-in list
	// of public resolvers). Without it, the MasterDnsVPN client balances the resolvers itself.
	// `true`, or an object with the pool's settings.
	SmartPool *SmartPoolOptions `json:"smart_pool,omitempty"`
	// PreTestDomain and PreTestRecordType are the plain query sent to each resolver before it
	// joins the pool. Defaults: www.google.com, a.
	PreTestDomain     string `json:"pretest_domain,omitempty"`
	PreTestRecordType string `json:"pretest_record_type,omitempty"`

	// Balancing chooses the resolver of each query: random, round-robin (default), least-loss,
	// lowest-latency, hybrid, loss-then-latency, least-loss-top-random or
	// least-loss-top-round-robin, or the number 1 to 8 of RESOLVER_BALANCING_STRATEGY.
	Balancing string `json:"balancing,omitempty"`
	// PacketDuplication sends every packet this many times, over different resolvers (1 to 10).
	PacketDuplication int `json:"packet_duplication,omitempty"`
	// SetupPacketDuplication sends the packets that open a connection this many times (up to 12).
	SetupPacketDuplication int `json:"setup_packet_duplication,omitempty"`
	// UploadCompression and DownloadCompression are off, zstd, lz4 or zlib.
	UploadCompression   string `json:"upload_compression,omitempty"`
	DownloadCompression string `json:"download_compression,omitempty"`
	// BaseEncode asks the server for base64 answers, for resolvers that damage binary records.
	BaseEncode bool `json:"base_encode,omitempty"`

	// MTU bounds for the test of each resolver, in bytes.
	MinUploadMTU   int `json:"min_upload_mtu,omitempty"`
	MaxUploadMTU   int `json:"max_upload_mtu,omitempty"`
	MinDownloadMTU int `json:"min_download_mtu,omitempty"`
	MaxDownloadMTU int `json:"max_download_mtu,omitempty"`
	// MTUTestTimeout is how long one MTU probe may take; MTUTestRetries how many times it is sent;
	// MTUTestParallelism how many resolvers are tested at once.
	MTUTestTimeout     badoption.Duration `json:"mtu_test_timeout,omitempty"`
	MTUTestRetries     int                `json:"mtu_test_retries,omitempty"`
	MTUTestParallelism int                `json:"mtu_test_parallelism,omitempty"`
	// AutoRemoveLowMTUResolvers drops the few resolvers that would pull the shared MTU down.
	AutoRemoveLowMTUResolvers *bool `json:"auto_remove_low_mtu_resolvers,omitempty"`
	// RecheckInactiveResolvers tests failed resolvers again in the background.
	RecheckInactiveResolvers *bool `json:"recheck_inactive_resolvers,omitempty"`
	// AutoDisableTimeoutResolvers stops using a resolver that only times out.
	AutoDisableTimeoutResolvers *bool `json:"auto_disable_timeout_resolvers,omitempty"`

	// Workers is the number of UDP read and write workers; ProcessWorkers the number of packet
	// processors (0: chosen from the machine).
	Workers        int `json:"workers,omitempty"`
	ProcessWorkers int `json:"process_workers,omitempty"`
	// ARQWindow is the size of the reliable delivery window, in packets.
	ARQWindow int `json:"arq_window,omitempty"`

	// ReadyTimeout is how long a connection waits for the tunnel to be ready (resolvers tested,
	// session opened) before it fails. Default 30s.
	ReadyTimeout badoption.Duration `json:"ready_timeout,omitempty"`
	// ConnectTimeout is how long a connection waits for the server to reach the destination.
	// Default 30s.
	ConnectTimeout badoption.Duration `json:"connect_timeout,omitempty"`
	// LogLevel of the MasterDnsVPN client's own messages: debug, info (default), warn or error.
	LogLevel string `json:"log_level,omitempty"`

	UDPOverTCP *UDPOverTCPOptions `json:"udp_over_tcp,omitempty"`
}

package masterdns

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

func validOptions() option.MasterDNSOptions {
	return option.MasterDNSOptions{
		Domains:   []string{"v.example.com"},
		Resolvers: []string{"127.0.0.1:5300", "10.0.0.0/30"},
		Key:       "0123456789abcdef0123456789abcdef",
	}
}

func newTestOutbound(t *testing.T, options option.MasterDNSOptions) *Outbound {
	t.Helper()
	out, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "masterdns-out", options)
	require.NoError(t, err)
	t.Cleanup(func() { out.(*Outbound).Close() })
	return out.(*Outbound)
}

func TestH_MasterDNSNewOutbound(t *testing.T) {
	t.Parallel()
	out := newTestOutbound(t, validOptions())
	require.Equal(t, C.TypeMasterDNS, out.Type())
	require.Equal(t, []string{N.NetworkTCP}, out.Network())
	require.Equal(t, "MasterDNS", out.DisplayType())
	cfg := out.Config()
	require.Equal(t, []string{"v.example.com"}, cfg.Domains)
	require.Len(t, cfg.Resolvers, 3) // one address and a /30 with two hosts
	require.Equal(t, "SOCKS5", cfg.ProtocolType)
	require.Equal(t, 1, cfg.DataEncryptionMethod) // xor by default
	require.Equal(t, 0, cfg.ListenPort)
	require.False(t, cfg.LocalDNSCachePersist)
	require.Equal(t, defaultReadyTimeout, out.readyTimeout)
	require.Equal(t, defaultConnectTimeout, out.connectTimeout)
	require.Nil(t, out.uotClient)
	require.Nil(t, out.pool)
	require.Equal(t, "www.google.com", out.options.PreTestDomain)
	require.Equal(t, "a", out.options.PreTestRecordType)
	require.Equal(t, 0, out.PoolResolvers())
}

func TestH_MasterDNSNewOutboundValidation(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*option.MasterDNSOptions){
		"domains":   func(o *option.MasterDNSOptions) { o.Domains = nil },
		"resolvers": func(o *option.MasterDNSOptions) { o.Resolvers = nil },
		"resolver":  func(o *option.MasterDNSOptions) { o.Resolvers = []string{"not an ip"} },
		"doh":       func(o *option.MasterDNSOptions) { o.Resolvers = []string{"https://dns.google/dns-query"} },
		"auto":      func(o *option.MasterDNSOptions) { o.Resolvers = []string{"auto"} },
		"pool cidr": func(o *option.MasterDNSOptions) {
			o.SmartPool = &option.SmartPoolOptions{Enabled: true}
			o.Resolvers = []string{"10.0.0.0/30"}
		},
		"pool quic": func(o *option.MasterDNSOptions) {
			o.SmartPool = &option.SmartPoolOptions{Enabled: true}
			o.Resolvers = []string{"quic://1.1.1.1"}
		},
		"key":         func(o *option.MasterDNSOptions) { o.Key = "" },
		"encryption":  func(o *option.MasterDNSOptions) { o.Encryption = "rot13" },
		"mode":        func(o *option.MasterDNSOptions) { o.Mode = "udp" },
		"balancing":   func(o *option.MasterDNSOptions) { o.Balancing = "fastest" },
		"balancing#":  func(o *option.MasterDNSOptions) { o.Balancing = "9" },
		"compression": func(o *option.MasterDNSOptions) { o.UploadCompression = "gzip" },
	}
	for name, mutate := range cases {
		options := validOptions()
		mutate(&options)
		_, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "masterdns-out", options)
		require.Error(t, err, name)
	}

	// no key is needed without encryption
	options := validOptions()
	options.Key = ""
	options.Encryption = "none"
	out := newTestOutbound(t, options)
	require.Equal(t, 0, out.Config().DataEncryptionMethod)
}

func TestH_MasterDNSTuning(t *testing.T) {
	t.Parallel()
	off := false
	options := validOptions()
	options.Encryption = "aes-256-gcm"
	options.Mode = "tcp"
	options.Balancing = "least-loss"
	options.PacketDuplication = 3
	options.SetupPacketDuplication = 5
	options.UploadCompression = "zstd"
	options.DownloadCompression = "lz4"
	options.BaseEncode = true
	options.MinUploadMTU = 40
	options.MaxUploadMTU = 160
	options.MinDownloadMTU = 120
	options.MaxDownloadMTU = 900
	options.MTUTestTimeout = badoption.Duration(1500 * time.Millisecond)
	options.MTUTestRetries = 3
	options.MTUTestParallelism = 8
	options.AutoRemoveLowMTUResolvers = &off
	options.RecheckInactiveResolvers = &off
	options.AutoDisableTimeoutResolvers = &off
	options.Workers = 2
	options.ProcessWorkers = 3
	options.ARQWindow = 700
	options.ReadyTimeout = badoption.Duration(5 * time.Second)
	options.ConnectTimeout = badoption.Duration(7 * time.Second)
	options.UDPOverTCP = &option.UDPOverTCPOptions{Enabled: true}

	out := newTestOutbound(t, options)
	cfg := out.Config()
	require.Equal(t, 5, cfg.DataEncryptionMethod)
	require.Equal(t, "TCP", cfg.ProtocolType)
	require.Equal(t, 3, cfg.ResolverBalancingStrategy)
	require.Equal(t, 3, cfg.PacketDuplicationCount)
	require.Equal(t, 5, cfg.SetupPacketDuplicationCount)
	require.Equal(t, 1, cfg.UploadCompressionType)
	require.Equal(t, 2, cfg.DownloadCompressionType)
	require.True(t, cfg.BaseEncodeData)
	require.Equal(t, 40, cfg.MinUploadMTU)
	require.Equal(t, 160, cfg.MaxUploadMTU)
	require.Equal(t, 120, cfg.MinDownloadMTU)
	require.Equal(t, 900, cfg.MaxDownloadMTU)
	require.Equal(t, 1.5, cfg.MTUTestTimeout)
	require.Equal(t, 3, cfg.MTUTestRetries)
	require.Equal(t, 8, cfg.MTUTestParallelism)
	require.False(t, cfg.AutoRemoveLowMTUServers)
	require.False(t, cfg.RecheckInactiveServersEnabled)
	require.False(t, cfg.AutoDisableTimeoutServers)
	require.Equal(t, 2, cfg.RX_TX_Workers)
	require.Equal(t, 3, cfg.TunnelProcessWorkers)
	require.Equal(t, 700, cfg.ARQWindowSize)
	require.Equal(t, 5*time.Second, out.readyTimeout)
	require.Equal(t, 7*time.Second, out.connectTimeout)
	require.NotNil(t, out.uotClient)

	// the number of a strategy works too
	options = validOptions()
	options.Balancing = "8"
	require.Equal(t, 8, newTestOutbound(t, options).Config().ResolverBalancingStrategy)
}

func TestH_MasterDNSDialBeforeStart(t *testing.T) {
	t.Parallel()
	out := newTestOutbound(t, validOptions())
	_, err := out.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	require.ErrorContains(t, err, "not started")
	_, err = out.DialContext(context.Background(), N.NetworkUDP, M.ParseSocksaddr("1.1.1.1:53"))
	require.ErrorContains(t, err, "not supported")
	_, err = out.ListenPacket(context.Background(), M.ParseSocksaddr("1.1.1.1:53"))
	require.ErrorContains(t, err, "UDP over TCP")
}

// After start, a connection waits for the session up to ready_timeout and then says why it is
// not ready. The resolver here answers nothing, so the client never becomes ready.
func TestH_MasterDNSDialWaitsForReady(t *testing.T) {
	t.Parallel()
	options := validOptions()
	options.Resolvers = []string{"127.0.0.1:9"}
	options.ReadyTimeout = badoption.Duration(300 * time.Millisecond)
	options.MTUTestTimeout = badoption.Duration(200 * time.Millisecond)
	options.MTUTestRetries = 1
	options.LogLevel = "error"
	out := newTestOutbound(t, options)
	require.NoError(t, out.PostStart())
	require.Equal(t, "MasterDNS", out.DisplayType())
	start := time.Now()
	_, err := out.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	require.ErrorContains(t, err, "not ready")
	require.GreaterOrEqual(t, time.Since(start), 300*time.Millisecond)
	require.NoError(t, out.Close())
	require.Error(t, func() error {
		_, err := out.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
		return err
	}())
}

func startLocalDNS(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Name == "probe.test." {
			rr, _ := dns.NewRR("probe.test. 60 IN A 192.0.2.1")
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	})}
	go server.ActivateAndServe()
	t.Cleanup(func() { server.Shutdown() })
	return pc.LocalAddr().String()
}

// With smart_pool the client's one resolver is the local pool; DoH, DoT and auto are accepted,
// and after start the resolvers that answer the probe join the pool.
func TestH_MasterDNSSmartPool(t *testing.T) {
	t.Parallel()
	answering := startLocalDNS(t)
	silent := startLocalDNS(t) // answers, but with no record for the probe name
	options := validOptions()
	options.SmartPool = &option.SmartPoolOptions{Enabled: true, LoadBalance: "weighted"}
	options.Resolvers = []string{answering, "dot://" + silent, "https://dns.example/dns-query", silent}
	options.PreTestDomain = "probe.test"
	options.LogLevel = "error"
	out := newTestOutbound(t, options)
	require.NotNil(t, out.pool)
	require.Len(t, out.candidates, 4)
	cfg := out.Config()
	require.Len(t, cfg.Resolvers, 1)
	require.Equal(t, "127.0.0.1", cfg.Resolvers[0].IP)
	host, _, err := net.SplitHostPort(out.pool.Addr())
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", host)

	require.NoError(t, out.PreStart())
	require.NoError(t, out.PostStart())
	select {
	case <-out.poolReady:
	case <-time.After(10 * time.Second):
		t.Fatal("no resolver joined the pool")
	}
	require.Eventually(t, func() bool { return out.PoolResolvers() >= 1 }, 5*time.Second, 50*time.Millisecond)
	require.NoError(t, out.Close())

	// auto expands to the built-in list
	options = validOptions()
	options.SmartPool = &option.SmartPoolOptions{Enabled: true}
	options.Resolvers = []string{"auto", "9.9.9.9"}
	out = newTestOutbound(t, options)
	require.Greater(t, len(out.candidates), 1000)
	require.NoError(t, out.Close())
}

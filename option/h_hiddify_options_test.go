package option

import (
	"context"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func hUnmarshal[T any](t *testing.T, content string) (T, error) {
	t.Helper()
	var value T
	err := json.UnmarshalContext(context.Background(), []byte(content), &value)
	return value, err
}

func hRoundTrip[T any](t *testing.T, content string) T {
	t.Helper()
	value, err := hUnmarshal[T](t, content)
	require.NoError(t, err)
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	decoded, err := hUnmarshal[T](t, string(encoded))
	require.NoError(t, err)
	require.Equal(t, value, decoded)
	return value
}

func TestH_RuleTunnelFields(t *testing.T) {
	t.Parallel()
	rule := hRoundTrip[Rule](t, `{"tunnel_source":"a","tunnel_destination":["b","c"],"outbound":"direct"}`)
	require.Equal(t, C.RuleTypeDefault, rule.Type)
	require.Equal(t, []string{"a"}, []string(rule.DefaultOptions.TunnelSource))
	require.Equal(t, []string{"b", "c"}, []string(rule.DefaultOptions.TunnelDestination))
	require.True(t, rule.DefaultOptions.IsValid())

	dnsRule := hRoundTrip[DNSRule](t, `{"tunnel_source":["a"],"server":"local"}`)
	require.Equal(t, []string{"a"}, []string(dnsRule.DefaultOptions.TunnelSource))

	headless := hRoundTrip[HeadlessRule](t, `{"tunnel_destination":"x"}`)
	require.Equal(t, []string{"x"}, []string(headless.DefaultOptions.TunnelDestination))
	require.True(t, headless.DefaultOptions.IsValid())
}

func TestH_RouteActionOverrideTunnelDestination(t *testing.T) {
	t.Parallel()
	action := hRoundTrip[RuleAction](t, `{"action":"route","outbound":"tunnel","override_tunnel_destination":"uuid-b"}`)
	require.Equal(t, C.RuleActionTypeRoute, action.Action)
	require.Equal(t, "uuid-b", action.RouteOptions.OverrideTunnelDestination)

	action = hRoundTrip[RuleAction](t, `{"action":"route-options","override_tunnel_destination":"uuid-c"}`)
	require.Equal(t, "uuid-c", action.RouteOptionsOptions.OverrideTunnelDestination)

	encoded, err := json.Marshal(RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: RouteActionOptions{Outbound: "x"}})
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "override_tunnel_destination")
}

func TestH_DNSRouteBypassIfFailed(t *testing.T) {
	t.Parallel()
	action := hRoundTrip[DNSRuleAction](t, `{"action":"route","server":"remote","bypass_if_failed":true}`)
	require.True(t, action.RouteOptions.BypassIfFailed)
	action = hRoundTrip[DNSRuleAction](t, `{"action":"route","server":"remote"}`)
	require.False(t, action.RouteOptions.BypassIfFailed)
}

func TestH_TunnelEndpointUsers(t *testing.T) {
	t.Parallel()
	user, err := hUnmarshal[TunnelUser](t, `{"uuid":"u","key":"k"}`)
	require.NoError(t, err)
	require.Equal(t, TunnelUser{UUID: "u", Key: "k"}, user)
}

func TestH_CacheFileAndExperimental(t *testing.T) {
	t.Parallel()
	experimental := hRoundTrip[ExperimentalOptions](t, `{
		"cache_file":{"enabled":true,"store_warp_config":true,"store_masque_config":true},
		"unified_delay":{"enabled":true},
		"monitoring":{"interval":"30s","urls":["https://a.example/generate_204"],"workers":3,"url_test_timeout":"5s"}
	}`)
	require.NotNil(t, experimental.CacheFile)
	require.True(t, experimental.CacheFile.StoreWARPConfig)
	require.True(t, experimental.CacheFile.StoreMASQUEConfig)
	require.NotNil(t, experimental.UnifiedDelay)
	require.True(t, experimental.UnifiedDelay.Enabled)
	require.NotNil(t, experimental.Monitoring)
	require.Equal(t, 30*time.Second, time.Duration(experimental.Monitoring.Interval))
	require.Equal(t, 3, experimental.Monitoring.Workers)

	empty := hRoundTrip[ExperimentalOptions](t, `{}`)
	require.Nil(t, empty.UnifiedDelay)
	require.Nil(t, empty.Monitoring)
}

func TestH_ProtocolFieldExtensions(t *testing.T) {
	t.Parallel()
	urltest := hRoundTrip[URLTestOutboundOptions](t, `{"outbounds":["a","b"],"urls":["https://x.example","https://y.example"]}`)
	require.Equal(t, []string{"https://x.example", "https://y.example"}, urltest.URLs)

	vlessOut := hRoundTrip[VLESSOutboundOptions](t, `{"server":"s","server_port":443,"uuid":"u","encryption":"mlkem768x25519plus.native.0rtt.abc"}`)
	require.Equal(t, "mlkem768x25519plus.native.0rtt.abc", vlessOut.Encryption)
	vlessIn := hRoundTrip[VLESSInboundOptions](t, `{"listen":"::","decryption":"none"}`)
	require.Equal(t, "none", vlessIn.Decryption)

	ss := hRoundTrip[ShadowsocksInboundOptions](t, `{"method":"aes-128-gcm","password":"p","obfs_mode":"http","obfs_host":"h.example"}`)
	require.Equal(t, "http", ss.ObfsMode)
	require.Equal(t, "h.example", ss.ObfsHost)

	tls := hRoundTrip[OutboundTLSOptions](t, `{"enabled":true,"tls_tricks":{"mixedcase_sni":true,"padding_mode":"random","padding_size":"10-20","padding_sni":"p.example"}}`)
	require.NotNil(t, tls.TLSTricks)
	require.True(t, tls.TLSTricks.MixedCaseSNI)
	require.Equal(t, "10-20", tls.TLSTricks.PaddingSize)

	ssh := hRoundTrip[SSHInboundOptions](t, `{"listen":"127.0.0.1","listen_port":2222,"users":[{"user":"a","password":"b"}],"host_key":"k","server_version":"SSH-2.0-x"}`)
	require.Len(t, ssh.Users, 1)
	require.Equal(t, "a", ssh.Users[0].User)
	require.Equal(t, []string{"k"}, []string(ssh.HostKey))

	balancer := hRoundTrip[BalancerOutboundOptions](t, `{"outbounds":["a"],"strategy":"lowest-delay","delay_acceptable_ratio":1.5,"ttl":"1m"}`)
	require.Equal(t, 1.5, balancer.DelayAcceptableRatio)
	require.Equal(t, time.Minute, time.Duration(balancer.TTL))

	pool := hRoundTrip[SmartDNSPoolServiceOptions](t, `{"listen":"127.0.0.1","listen_port":19876,"upstreams":[{"type":"udp","address":"1.1.1.1:53","weight":2}],"load_balance":"weighted","deadline":"5s"}`)
	require.Len(t, pool.Upstreams, 1)
	require.Equal(t, 2, pool.Upstreams[0].Weight)
	require.Equal(t, 5*time.Second, time.Duration(pool.Deadline))

	dnstt := hRoundTrip[DnsttOptions](t, `{"pubkey":"pk","domain":"t.example","resolvers":["auto","8.8.8.8"],"max-qname-len":101,"idle-timeout":"10s","smart_pool":true}`)
	require.Equal(t, "pk", dnstt.PublicKey)
	require.NotNil(t, dnstt.MaxQnameLen)
	require.Equal(t, 101, *dnstt.MaxQnameLen)
	require.NotNil(t, dnstt.IdleTimeout)
	require.True(t, dnstt.SmartPool)
	require.Nil(t, dnstt.RPS)
}

func TestH_DNSServerOptionsHiddify(t *testing.T) {
	t.Parallel()
	sdns := hRoundTrip[SDNSDNSServerOptions](t, `{"server":"1.1.1.1","stamp":"sdns://AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5"}`)
	require.Contains(t, sdns.Stamp, "sdns://")
	multi := hRoundTrip[MultiDNSServerOptions](t, `{"servers":["a","b"],"parallel":true,"ignore_ranges":["10.0.0.0/8"]}`)
	require.Equal(t, []string{"a", "b"}, multi.Servers)
	require.True(t, multi.Parallel)
	require.Len(t, multi.IgnoreRanges, 1)
}

func TestH_WARPAndAwgOptions(t *testing.T) {
	t.Parallel()
	warp := hRoundTrip[WARPEndpointOptions](t, `{
		"server":"engage.cloudflareclient.com","server_port":2408,"mtu":1280,
		"profile":{"id":"i","private_key":"pk","auth_token":"t","recreate":true,"license":"l"},
		"unique_identifier":"uid",
		"awg":{"jc":4,"jmin":40,"jmax":70},
		"private_key":"cfg-pk",
		"interface":{"addresses":{"v4":"172.16.0.2","v6":"2606::1"}},
		"peers":[{"public_key":"peer","endpoint":{"host":"h","ports":[2408,500]}}]
	}`)
	require.Equal(t, uint32(1280), warp.MTU)
	require.Equal(t, "pk", warp.Profile.PrivateKey)
	require.True(t, warp.Profile.Recreate)
	require.NotNil(t, warp.AWG)
	require.True(t, warp.AWG.IsAvailble())
	require.NotNil(t, warp.WARPConfig)
	require.Equal(t, "cfg-pk", warp.WARPConfig.PrivateKey)
	require.Equal(t, "172.16.0.2", warp.WARPConfig.Interface.Addresses.V4)
	require.Len(t, warp.WARPConfig.Peers, 1)
	require.Equal(t, []int{2408, 500}, warp.WARPConfig.Peers[0].Endpoint.Ports)

	plain := hRoundTrip[WARPEndpointOptions](t, `{"profile":{"id":"x"}}`)
	require.Nil(t, plain.AWG)
	require.Nil(t, plain.WARPConfig)

	var nilAwg *AwgOptions
	require.False(t, nilAwg.IsAvailble())
	require.False(t, (&AwgOptions{}).IsAvailble())
	for _, awg := range []AwgOptions{{Jc: 1}, {S4: 1}, {H1: "1"}, {H4: "x"}, {I1: "<b 0x01>"}, {I5: "x"}} {
		require.True(t, awg.IsAvailble(), "%+v", awg)
	}

	endpoint := hRoundTrip[AwgEndpointOptions](t, `{"private_key":"k","address":["10.0.0.2/32"],"awg":{"jc":3,"s1":10,"h1":"1"},"peers":[{"address":"1.2.3.4","port":51820,"public_key":"p","allowed_ips":["0.0.0.0/0"]}]}`)
	require.True(t, endpoint.Awg.IsAvailble())
	require.Len(t, endpoint.Peers, 1)
	require.Equal(t, uint16(51820), endpoint.Peers[0].Port)
}

func TestH_RandBetween(t *testing.T) {
	t.Parallel()
	require.Equal(t, 5, RandBetween(5, 5))
	seen := make(map[int]bool)
	for i := 0; i < 2000; i++ {
		value := RandBetween(3, 6)
		require.GreaterOrEqual(t, value, 3)
		require.LessOrEqual(t, value, 6)
		seen[value] = true
	}
	require.Len(t, seen, 4)
}

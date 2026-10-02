package smart_dns_pool

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"

	multidns "github.com/hiddify/hmrd_multi_resolver_dns"
	"github.com/stretchr/testify/require"
)

func TestH_ProtocolFromString(t *testing.T) {
	t.Parallel()
	cases := map[string]multidns.Protocol{
		"":      multidns.ProtoUDP,
		"udp":   multidns.ProtoUDP,
		"tcp":   multidns.ProtoTCP,
		"tls":   multidns.ProtoDoT,
		"dot":   multidns.ProtoDoT,
		"https": multidns.ProtoDoH,
		"doh":   multidns.ProtoDoH,
	}
	for input, expected := range cases {
		proto, err := protocolFromString(input)
		require.NoError(t, err, input)
		require.Equal(t, expected, proto, input)
	}
	for _, input := range []string{"UDP", "quic", "h3", "doq", " udp"} {
		_, err := protocolFromString(input)
		require.ErrorContains(t, err, "unsupported upstream type", input)
	}
}

func TestH_LBFromString(t *testing.T) {
	t.Parallel()
	require.Equal(t, multidns.LBWeighted, lbFromString("weighted"))
	require.Equal(t, multidns.LBLowestLatency, lbFromString("lowest_latency"))
	require.Equal(t, multidns.LBRoundRobin, lbFromString("roundrobin"))
	require.Equal(t, multidns.LBRoundRobin, lbFromString(""))
	require.Equal(t, multidns.LBRoundRobin, lbFromString("unknown"))
}

func TestH_NewServiceValidation(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().NewLogger("test")
	_, err := NewService(context.Background(), logger, "t", option.SmartDNSPoolServiceOptions{
		ListenOptions: option.ListenOptions{ListenPort: 19000},
		Upstreams: []option.SmartDNSPoolUpstreamOptions{
			{Type: "udp", Address: "127.0.0.1:53"},
			{Type: "tcp"},
		},
	})
	require.ErrorContains(t, err, "upstream #1 missing address")

	_, err = NewService(context.Background(), logger, "t", option.SmartDNSPoolServiceOptions{
		ListenOptions: option.ListenOptions{ListenPort: 19000},
		Upstreams: []option.SmartDNSPoolUpstreamOptions{
			{Type: "udp", Address: "127.0.0.1:53"},
			{Type: "quic", Address: "127.0.0.1:853"},
		},
	})
	require.ErrorContains(t, err, "upstream #1")
	require.ErrorContains(t, err, "unsupported upstream type")
}

func TestH_NewServiceListenAddress(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().NewLogger("test")
	upstreams := []option.SmartDNSPoolUpstreamOptions{{Address: "127.0.0.1:53"}}

	instance, err := NewService(context.Background(), logger, "pool", option.SmartDNSPoolServiceOptions{
		ListenOptions: option.ListenOptions{ListenPort: 19876},
		Upstreams:     upstreams,
	})
	require.NoError(t, err)
	service := instance.(*Service)
	require.Equal(t, "127.0.0.1:19876", service.listenAddr)
	require.Equal(t, C.TypeSmartDNSPool, service.Type())
	require.Equal(t, "pool", service.Tag())

	listen := badoption.Addr(netip.MustParseAddr("::1"))
	instance, err = NewService(context.Background(), logger, "pool", option.SmartDNSPoolServiceOptions{
		ListenOptions: option.ListenOptions{Listen: &listen, ListenPort: 5353},
		Upstreams:     upstreams,
	})
	require.NoError(t, err)
	require.Equal(t, "[::1]:5353", instance.(*Service).listenAddr)

	listen4 := badoption.Addr(netip.MustParseAddr("0.0.0.0"))
	instance, err = NewService(context.Background(), logger, "pool", option.SmartDNSPoolServiceOptions{
		ListenOptions: option.ListenOptions{Listen: &listen4, ListenPort: 53},
		Upstreams:     upstreams,
	})
	require.NoError(t, err)
	require.Equal(t, "0.0.0.0:53", instance.(*Service).listenAddr)
}

func TestH_ServiceStartOtherStagesAndCloseIdle(t *testing.T) {
	t.Parallel()
	instance, err := NewService(context.Background(), log.NewNOPFactory().NewLogger("test"), "pool", option.SmartDNSPoolServiceOptions{
		ListenOptions: option.ListenOptions{ListenPort: 1},
		Upstreams:     []option.SmartDNSPoolUpstreamOptions{{Address: "127.0.0.1:53"}},
	})
	require.NoError(t, err)
	service := instance.(*Service)
	for _, stage := range []adapter.StartStage{adapter.StartStateInitialize, adapter.StartStatePostStart, adapter.StartStateStarted} {
		require.NoError(t, service.Start(stage))
	}
	require.Nil(t, service.mgr)
	require.Nil(t, service.server)
	require.NoError(t, service.Close())
	require.NoError(t, service.Close())
}

func TestH_SmartDNSPoolOptionsJSON(t *testing.T) {
	t.Parallel()
	var options option.SmartDNSPoolServiceOptions
	err := json.Unmarshal([]byte(`{
		"listen": "127.0.0.1",
		"listen_port": 19876,
		"upstreams": [
			{"type": "udp", "address": "1.1.1.1:53", "weight": 3, "name": "cf"},
			{"type": "https", "address": "https://dns.example/dns-query"}
		],
		"load_balance": "weighted",
		"deadline": "3s",
		"per_attempt": "500ms",
		"probe_interval": "10s",
		"down_after": 4
	}`), &options)
	require.NoError(t, err)
	require.EqualValues(t, 19876, options.ListenPort)
	require.NotNil(t, options.Listen)
	require.Equal(t, "127.0.0.1", options.Listen.Build(netip.Addr{}).String())
	require.Len(t, options.Upstreams, 2)
	require.Equal(t, option.SmartDNSPoolUpstreamOptions{Type: "udp", Address: "1.1.1.1:53", Weight: 3, Name: "cf"}, options.Upstreams[0])
	require.Equal(t, "https", options.Upstreams[1].Type)
	require.Equal(t, "weighted", options.LoadBalance)
	require.Equal(t, 3*time.Second, time.Duration(options.Deadline))
	require.Equal(t, 500*time.Millisecond, time.Duration(options.PerAttempt))
	require.Equal(t, 10*time.Second, time.Duration(options.ProbeInterval))
	require.Equal(t, 4, options.DownAfter)
}

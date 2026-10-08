package box_test

import (
	"context"
	"io"
	"net"
	"sort"
	"strconv"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func hFreeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func hParseOptions(t *testing.T, ctx context.Context, config string) option.Options {
	t.Helper()
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
	require.NoError(t, err)
	return options
}

const hReloadBase = `{
	"log": {"disabled": true},
	"outbounds": [
		{"type": "selector", "tag": "select", "outbounds": ["a", "b"], "default": "a"},
		{"type": "direct", "tag": "a"},
		{"type": "direct", "tag": "b"},
		{"type": "direct", "tag": "keep"},
		{"type": "direct", "tag": "gone"}
	],
	"route": {"final": "select"}
}`

func hStartReloadBox(t *testing.T) (*box.Box, context.Context, option.Options) {
	t.Helper()
	ctx := include.Context(context.Background())
	options := hParseOptions(t, ctx, hReloadBase)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	t.Cleanup(func() { instance.Close() })
	require.NoError(t, instance.Start())
	return instance, ctx, options
}

func hOutbound(t *testing.T, instance *box.Box, tag string) adapter.Outbound {
	t.Helper()
	outbound, loaded := instance.Outbound().Outbound(tag)
	require.True(t, loaded, tag)
	return outbound
}

func TestH_HotReloadOutbounds(t *testing.T) {
	instance, ctx, _ := hStartReloadBox(t)
	selector := hOutbound(t, instance, "select").(interface {
		SelectOutbound(string) bool
		Selected(string) adapter.Outbound
	})
	require.True(t, selector.SelectOutbound("b"))
	keep := hOutbound(t, instance, "keep")
	b := hOutbound(t, instance, "b")
	oldSelect := hOutbound(t, instance, "select")

	// b changes, c is added (and joins the selector), gone is removed
	newOptions := hParseOptions(t, ctx, `{
		"log": {"disabled": true},
		"outbounds": [
			{"type": "selector", "tag": "select", "outbounds": ["a", "b", "c"], "default": "a"},
			{"type": "direct", "tag": "a"},
			{"type": "direct", "tag": "b", "tcp_fast_open": true},
			{"type": "direct", "tag": "c"},
			{"type": "direct", "tag": "keep"}
		],
		"route": {"final": "select"}
	}`)
	result, err := instance.HotReloadWithResult(context.Background(), &newOptions)
	require.NoError(t, err)
	require.Equal(t, []string{"c"}, result.Outbounds.Created)
	require.Equal(t, []string{"b", "select"}, result.Outbounds.Replaced, "the selector holds the old b")
	require.Equal(t, []string{"gone"}, result.Outbounds.Removed)

	require.Same(t, keep, hOutbound(t, instance, "keep"), "unchanged outbounds keep running")
	order := make([]string, 0)
	for _, outbound := range instance.Outbound().Outbounds() {
		order = append(order, outbound.Tag())
	}
	require.Equal(t, []string{"select", "a", "b", "keep", "c"}, order, "replaced outbounds keep their place, new ones are appended")
	require.NotSame(t, b, hOutbound(t, instance, "b"))
	newSelect := hOutbound(t, instance, "select")
	require.NotSame(t, oldSelect, newSelect)
	require.Equal(t, []string{"a", "b", "c"}, newSelect.(adapter.OutboundGroup).All())
	require.Equal(t, "b", newSelect.(adapter.OutboundGroup).Selected(N.NetworkTCP).Tag(), "selection is kept")
	require.Same(t, hOutbound(t, instance, "b"), newSelect.(adapter.OutboundGroup).Selected(N.NetworkTCP), "and uses the new b")
	_, loaded := instance.Outbound().Outbound("gone")
	require.False(t, loaded)
	require.Equal(t, "select", instance.Outbound().Default().Tag())

	histories := monitoring.Get(ctx).OutboundsHistory("select")
	tags := make([]string, 0, len(histories))
	for tag := range histories {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	require.Equal(t, []string{"a", "b", "c"}, tags, "monitoring follows the new group")

	// traffic goes through the reloaded selector
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err == nil {
			io.Copy(conn, conn)
			conn.Close()
		}
	}()
	dialCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := newSelect.DialContext(dialCtx, N.NetworkTCP, M.SocksaddrFromNet(echo.Addr()))
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	reply := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, "ping", string(reply))

	// nothing changed: nothing to do
	result, err = instance.HotReloadWithResult(context.Background(), &newOptions)
	require.NoError(t, err)
	require.True(t, result.IsEmpty())
}

func TestH_HotReloadDetourFollowsReplacedOutbound(t *testing.T) {
	instance, ctx, _ := hStartReloadBox(t)
	options := hParseOptions(t, ctx, `{
		"log": {"disabled": true},
		"outbounds": [
			{"type": "selector", "tag": "select", "outbounds": ["a", "b", "front"], "default": "a"},
			{"type": "direct", "tag": "a"},
			{"type": "direct", "tag": "b"},
			{"type": "socks", "tag": "front", "server": "127.0.0.1", "server_port": 1080, "detour": "keep"},
			{"type": "direct", "tag": "keep"},
			{"type": "direct", "tag": "gone"}
		],
		"route": {"final": "select"}
	}`)
	_, err := instance.HotReloadWithResult(context.Background(), &options)
	require.NoError(t, err)
	front := hOutbound(t, instance, "front")

	// keep changes: front dials through it, so front is recreated too
	changed := hParseOptions(t, ctx, `{
		"log": {"disabled": true},
		"outbounds": [
			{"type": "selector", "tag": "select", "outbounds": ["a", "b", "front"], "default": "a"},
			{"type": "direct", "tag": "a"},
			{"type": "direct", "tag": "b"},
			{"type": "socks", "tag": "front", "server": "127.0.0.1", "server_port": 1080, "detour": "keep"},
			{"type": "direct", "tag": "keep", "tcp_fast_open": true},
			{"type": "direct", "tag": "gone"}
		],
		"route": {"final": "select"}
	}`)
	result, err := instance.HotReloadWithResult(context.Background(), &changed)
	require.NoError(t, err)
	require.Equal(t, []string{"front", "keep", "select"}, result.Outbounds.Replaced)
	require.NotSame(t, front, hOutbound(t, instance, "front"))
}

func TestH_HotReloadOutboundBecomesEndpoint(t *testing.T) {
	instance, ctx, _ := hStartReloadBox(t)
	newOptions := hParseOptions(t, ctx, `{
		"log": {"disabled": true},
		"outbounds": [
			{"type": "selector", "tag": "select", "outbounds": ["a", "b"], "default": "a"},
			{"type": "direct", "tag": "a"},
			{"type": "direct", "tag": "keep"},
			{"type": "direct", "tag": "gone"}
		],
		"endpoints": [
			{"type": "hinvalid", "tag": "b", "original_type": "wireguard"}
		],
		"route": {"final": "select"}
	}`)
	result, err := instance.HotReloadWithResult(context.Background(), &newOptions)
	require.NoError(t, err)
	require.Equal(t, []string{"b", "select"}, result.Outbounds.Replaced)
	endpoint, loaded := instance.Endpoint().Get("b")
	require.True(t, loaded, "b is now an endpoint")
	require.Same(t, adapter.Outbound(endpoint), hOutbound(t, instance, "b"))
	for _, outbound := range instance.Outbound().Outbounds() {
		require.NotEqual(t, "b", outbound.Tag(), "b left the outbound manager")
	}
}

func TestH_HotReloadRejectsOtherChanges(t *testing.T) {
	instance, ctx, _ := hStartReloadBox(t)
	a := hOutbound(t, instance, "a")
	newOptions := hParseOptions(t, ctx, `{
		"log": {"disabled": true},
		"outbounds": [
			{"type": "selector", "tag": "select", "outbounds": ["a", "b"], "default": "a"},
			{"type": "direct", "tag": "a", "tcp_fast_open": true},
			{"type": "direct", "tag": "b"},
			{"type": "direct", "tag": "keep"},
			{"type": "direct", "tag": "gone"}
		],
		"route": {"final": "select", "find_process": true},
		"ntp": {"enabled": true, "server": "time.example.com"}
	}`)
	err := instance.HotReload(context.Background(), &newOptions)
	require.ErrorContains(t, err, "hot reload cannot change: ntp, route.find_process")
	require.Same(t, a, hOutbound(t, instance, "a"), "nothing is applied")
}

// a TUN change is reloadable; IsTunChanged tells it apart so a caller can choose to restart instead
func TestH_HotReloadTUNChanges(t *testing.T) {
	ctx := include.Context(context.Background())
	withTUN := func(address string) option.Options {
		return hParseOptions(t, ctx, `{
			"log": {"disabled": true},
			"inbounds": [
				{"type": "tun", "tag": "tun-in", "address": ["`+address+`"]},
				{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}
			],
			"outbounds": [{"type": "direct", "tag": "direct"}]
		}`)
	}
	base := withTUN("172.19.0.1/30")
	changedTUN := withTUN("172.20.0.1/30")
	withoutTUN := withTUN("172.19.0.1/30")
	withoutTUN.Inbounds = withoutTUN.Inbounds[1:]
	require.NoError(t, box.CheckHotReload(ctx, base, changedTUN))
	require.NoError(t, box.CheckHotReload(ctx, base, withoutTUN))

	// a box running without TUN (creating one needs privileges here)
	instance, err := box.New(box.Options{Context: ctx, Options: hParseOptions(t, ctx, `{"log": {"disabled": true}, "outbounds": [{"type": "direct", "tag": "direct"}]}`)})
	require.NoError(t, err)
	defer instance.Close()
	changed, err := instance.IsTunChanged(ctx, &base)
	require.NoError(t, err)
	require.True(t, changed, "a TUN inbound is added")
	same := hParseOptions(t, ctx, `{"inbounds": [{"type": "mixed", "tag": "m", "listen": "127.0.0.1", "listen_port": 2080}], "outbounds": [{"type": "direct", "tag": "direct"}]}`)
	changed, err = instance.IsTunChanged(ctx, &same)
	require.NoError(t, err)
	require.False(t, changed, "other inbounds are not TUN")
}

func TestH_HotReloadRouteAndDNS(t *testing.T) {
	ctx := include.Context(context.Background())
	config := func(final, dnsFinal, ruleTarget string, extraRuleSet string) string {
		return `{
			"log": {"disabled": true},
			"dns": {
				"servers": [
					{"type": "udp", "tag": "dns-a", "server": "127.0.0.1", "server_port": 5353},
					{"type": "udp", "tag": "dns-b", "server": "127.0.0.2"}
				],
				"rules": [{"rule_set": "local-set", "server": "dns-b"}],
				"final": "` + dnsFinal + `"
			},
			"outbounds": [
				{"type": "direct", "tag": "a"},
				{"type": "direct", "tag": "b"},
				{"type": "block", "tag": "blocked"}
			],
			"route": {
				"rule_set": [
					{"type": "inline", "tag": "local-set", "rules": [{"domain_suffix": "example.com"}]}` + extraRuleSet + `
				],
				"rules": [{"rule_set": "local-set", "outbound": "` + ruleTarget + `"}],
				"final": "` + final + `"
			}
		}`
	}
	oldOptions := hParseOptions(t, ctx, config("a", "dns-a", "blocked", ""))
	instance, err := box.New(box.Options{Context: ctx, Options: oldOptions})
	require.NoError(t, err)
	defer instance.Close()
	require.NoError(t, instance.Start())
	router := instance.Router()
	localSet, loaded := router.RuleSet("local-set")
	require.True(t, loaded)
	oldRules := router.Rules()
	dnsTransport := service.FromContext[adapter.DNSTransportManager](ctx)
	dnsA, _ := dnsTransport.Transport("dns-a")
	dnsB, _ := dnsTransport.Transport("dns-b")
	require.Equal(t, "dns-a", dnsTransport.Default().Tag())

	// route: rule target, final and an added rule-set; dns: a changed server and final
	newOptions := hParseOptions(t, ctx, config("b", "dns-b", "a", `,
					{"type": "inline", "tag": "other-set", "rules": [{"domain_suffix": "example.org"}]}`))
	newOptions.DNS.Servers[0] = hParseOptions(t, ctx, `{"dns": {"servers": [{"type": "udp", "tag": "dns-a", "server": "127.0.0.1", "server_port": 5354}]}}`).DNS.Servers[0]
	result, err := instance.HotReloadWithResult(context.Background(), &newOptions)
	require.NoError(t, err)
	require.True(t, result.RouteRules)
	require.True(t, result.RouteFinal)
	require.True(t, result.DNSFinal)
	require.True(t, result.DNSRules, "DNS rules use the route rule-sets")
	require.Equal(t, []string{"dns-a"}, result.DNSServers.Replaced)
	require.True(t, result.Outbounds.IsEmpty())

	require.Equal(t, "b", instance.Outbound().Default().Tag(), "route.final")
	require.Equal(t, "dns-b", dnsTransport.Default().Tag(), "dns.final")
	newDNSA, _ := dnsTransport.Transport("dns-a")
	require.NotSame(t, dnsA, newDNSA)
	sameDNSB, _ := dnsTransport.Transport("dns-b")
	require.Same(t, dnsB, sameDNSB, "an unchanged DNS server keeps running")
	reusedSet, _ := router.RuleSet("local-set")
	require.Same(t, localSet, reusedSet, "an unchanged rule-set is kept, not loaded again")
	_, loaded = router.RuleSet("other-set")
	require.True(t, loaded)
	newRules := router.Rules()
	require.Len(t, newRules, 1)
	require.NotSame(t, oldRules[0], newRules[0])
	action, isRoute := newRules[0].Action().(*R.RuleActionRoute)
	require.True(t, isRoute)
	require.Equal(t, "a", action.Outbound, "the rule now routes to a")
}

func TestH_HotReloadInbounds(t *testing.T) {
	ctx := include.Context(context.Background())
	port1, port2 := hFreeTCPPort(t), hFreeTCPPort(t)
	config := func(port int, extra string) string {
		return `{
			"log": {"disabled": true},
			"inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": ` + strconv.Itoa(port) + `}` + extra + `],
			"outbounds": [{"type": "direct", "tag": "direct"}]
		}`
	}
	instance, err := box.New(box.Options{Context: ctx, Options: hParseOptions(t, ctx, config(port1, ""))})
	require.NoError(t, err)
	defer instance.Close()
	require.NoError(t, instance.Start())
	listening := func(port int) bool {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}
	require.True(t, listening(port1))

	// the port changes and an inbound is added
	port3 := hFreeTCPPort(t)
	newOptions := hParseOptions(t, ctx, config(port2, `,
		{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(port3)+`}`))
	result, err := instance.HotReloadWithResult(context.Background(), &newOptions)
	require.NoError(t, err)
	require.Equal(t, []string{"mixed-in"}, result.Inbounds.Replaced)
	require.Equal(t, []string{"socks-in"}, result.Inbounds.Created)
	require.False(t, listening(port1), "the old listener is closed")
	require.True(t, listening(port2))
	require.True(t, listening(port3))

	// same port, another option: the old inbound is closed first, so the port is free again
	samePort := hParseOptions(t, ctx, config(port2, ``))
	samePort.Inbounds[0] = hParseOptions(t, ctx, `{"inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(port2)+`, "users": [{"username": "u", "password": "p"}]}]}`).Inbounds[0]
	result, err = instance.HotReloadWithResult(context.Background(), &samePort)
	require.NoError(t, err)
	require.Equal(t, []string{"mixed-in"}, result.Inbounds.Replaced)
	require.Equal(t, []string{"socks-in"}, result.Inbounds.Removed)
	require.True(t, listening(port2))
	require.False(t, listening(port3))
}

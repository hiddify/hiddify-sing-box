package box_test

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type hDiscardPacketWriter struct{}

func (hDiscardPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer.Release()
	return nil
}

// HijackDNSPacket runs on the TUN's packet loop, so it must hand the query off at once even
// when the DNS server's detour hangs; otherwise every packet waits for the DNS timeout.
func TestH_HijackDNSPacketDoesNotBlockOnDeadDetour(t *testing.T) {
	// a SOCKS server that accepts and never answers the handshake
	blackhole, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer blackhole.Close()
	go func() {
		for {
			conn, err := blackhole.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
		"log": {"disabled": true},
		"dns": {"servers": [{"type": "udp", "tag": "remote", "server": "127.0.0.1", "server_port": 53, "detour": "dead"}]},
		"outbounds": [
			{"type": "direct", "tag": "direct"},
			{"type": "socks", "tag": "dead", "server": "127.0.0.1", "server_port": `+strconv.Itoa(blackhole.Addr().(*net.TCPAddr).Port)+`}
		]
	}`))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	defer instance.Close()
	require.NoError(t, instance.Start())

	query := new(mDNS.Msg)
	query.SetQuestion("example.com.", mDNS.TypeA)
	for i := range 3 {
		query.Id = uint16(i + 1)
		payload, err := query.Pack()
		require.NoError(t, err)
		start := time.Now()
		instance.Router().HijackDNSPacket(ctx, payload, hDiscardPacketWriter{}, adapter.InboundContext{
			Inbound:     "tun-in",
			InboundType: C.TypeTun,
			Network:     N.NetworkUDP,
			Source:      M.ParseSocksaddr("172.19.0.1:40000"),
			Destination: M.ParseSocksaddr("172.19.0.2:53"),
		})
		require.Less(t, time.Since(start), 500*time.Millisecond, "query %d blocked the caller", i)
	}
}

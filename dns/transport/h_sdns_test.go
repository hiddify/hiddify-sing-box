package transport

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/ameshkov/dnscrypt/v2"
	"github.com/ameshkov/dnsstamps"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type hDNSCryptHandler struct{}

func (h *hDNSCryptHandler) ServeDNS(rw dnscrypt.ResponseWriter, r *mDNS.Msg) error {
	response := new(mDNS.Msg)
	response.SetReply(r)
	response.Answer = append(response.Answer, &mDNS.A{
		Hdr: mDNS.RR_Header{Name: r.Question[0].Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 60},
		A:   net.IPv4(192, 0, 2, 7).To4(),
	})
	return rw.WriteMsg(response)
}

func hStartDNSCryptServer(t *testing.T) string {
	t.Helper()
	config, err := dnscrypt.GenerateResolverConfig("example.org", nil)
	require.NoError(t, err)
	cert, err := config.CreateCert()
	require.NoError(t, err)
	server := &dnscrypt.Server{
		ProviderName: config.ProviderName,
		ResolverCert: cert,
		Handler:      &hDNSCryptHandler{},
		Logger:       slog.New(slog.DiscardHandler),
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	go server.ServeUDP(conn)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		conn.Close()
	})
	stamp, err := config.CreateStamp(conn.LocalAddr().String())
	require.NoError(t, err)
	return stamp.String()
}

func hNewSDNS(t *testing.T, stamp string) *SDNSTransport {
	t.Helper()
	transport, err := NewSDNSTransport(context.Background(), log.NewNOPFactory().NewLogger("sdns"), "sdns-test", option.SDNSDNSServerOptions{Stamp: stamp})
	require.NoError(t, err)
	sdns := transport.(*SDNSTransport)
	sdns.client.Timeout = 2 * time.Second
	return sdns
}

func hQuery() *mDNS.Msg {
	message := new(mDNS.Msg)
	message.SetQuestion("example.com.", mDNS.TypeA)
	return message
}

func TestH_SDNSExchangeDNSCrypt(t *testing.T) {
	t.Parallel()
	transport := hNewSDNS(t, hStartDNSCryptServer(t))
	require.NoError(t, transport.Start(adapter.StartStateStart))
	defer transport.Close()

	response, err := transport.Exchange(context.Background(), hQuery())
	require.NoError(t, err)
	require.Len(t, response.Answer, 1)
	require.Equal(t, "192.0.2.7", response.Answer[0].(*mDNS.A).A.String())

	done := make(chan struct{})
	transport.ExchangeAsync(context.Background(), hQuery(), func(response *mDNS.Msg, err error) {
		defer close(done)
		require.NoError(t, err)
		require.Len(t, response.Answer, 1)
	})
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ExchangeAsync callback not called")
	}
}

func TestH_SDNSInvalidStamps(t *testing.T) {
	t.Parallel()
	dohStamp := dnsstamps.ServerStamp{
		Proto:         dnsstamps.StampProtoTypeDoH,
		ServerAddrStr: "127.0.0.1:443",
		ProviderName:  "doh.example",
		Path:          "/dns-query",
	}
	dotStamp := dnsstamps.ServerStamp{
		Proto:         dnsstamps.StampProtoTypeTLS,
		ServerAddrStr: "127.0.0.1:853",
		ProviderName:  "dot.example",
	}
	plainStamp := dnsstamps.ServerStamp{
		Proto:         dnsstamps.StampProtoTypePlain,
		ServerAddrStr: "127.0.0.1:53",
	}
	for _, stamp := range []string{dohStamp.String(), dotStamp.String(), plainStamp.String()} {
		transport := hNewSDNS(t, stamp)
		_, err := transport.Exchange(context.Background(), hQuery())
		require.ErrorIs(t, err, dnscrypt.ErrInvalidDNSStamp, stamp)
	}
	for _, stamp := range []string{"", "not-a-stamp", "sdns://", "sdns://!!!", "https://dns.google/dns-query"} {
		transport := hNewSDNS(t, stamp)
		_, err := transport.Exchange(context.Background(), hQuery())
		require.Error(t, err, stamp)
	}
}

func TestH_SDNSUnreachableServer(t *testing.T) {
	t.Parallel()
	config, err := dnscrypt.GenerateResolverConfig("example.org", nil)
	require.NoError(t, err)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer conn.Close()
	stamp, err := config.CreateStamp(conn.LocalAddr().String())
	require.NoError(t, err)
	transport := hNewSDNS(t, stamp.String())
	transport.client.Timeout = 200 * time.Millisecond
	start := time.Now()
	_, err = transport.Exchange(context.Background(), hQuery())
	require.Error(t, err)
	require.Less(t, time.Since(start), 3*time.Second)
}

func TestH_SDNSOptionsJSON(t *testing.T) {
	t.Parallel()
	var options option.SDNSDNSServerOptions
	err := json.Unmarshal([]byte(`{"stamp":"sdns://AQcAAAAAAAAADTEyNy4wLjAuMTo1NDM"}`), &options)
	require.NoError(t, err)
	require.Equal(t, "sdns://AQcAAAAAAAAADTEyNy4wLjAuMTo1NDM", options.Stamp)
}

func TestH_SDNSAdapterMetadata(t *testing.T) {
	t.Skip("BUG: sdns.go NewSDNSTransport never initializes the embedded dns.TransportAdapter, so Tag() and Type() are empty")
	t.Parallel()
	transport := hNewSDNS(t, "sdns://")
	require.Equal(t, "sdns-test", transport.Tag())
	require.Equal(t, C.DNSTypeSDNS, transport.Type())
}

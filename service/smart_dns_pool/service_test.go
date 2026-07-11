package smart_dns_pool

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/miekg/dns"
)

// startUDPUpstream spins up a tiny in-process miekg/dns UDP server that
// answers any A query with answerIP, simulating a recursive resolver.
func startUDPUpstream(t *testing.T, answerIP string) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			r := new(dns.Msg)
			r.SetReply(q)
			r.Rcode = dns.RcodeSuccess
			if len(q.Question) > 0 && q.Question[0].Qtype == dns.TypeA {
				r.Answer = append(r.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name: q.Question[0].Name, Rrtype: dns.TypeA,
						Class: dns.ClassINET, Ttl: 30,
					},
					A: net.ParseIP(answerIP).To4(),
				})
			}
			_ = w.WriteMsg(r)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	return pc.LocalAddr().String(), func() { _ = srv.Shutdown() }
}

// freePort returns a port number guaranteed to be free at the moment of
// the call (the listener is closed before returning, so technically there's
// a TOCTOU window, but it's fine for tests).
func freePort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := l.LocalAddr().(*net.UDPAddr).Port
	l.Close()
	return uint16(port)
}

// digOnce sends a single A query for `name` to addr (host:port) over UDP and
// returns the resolved IP string, or fatals.
func digOnce(t *testing.T, addr, name string) string {
	t.Helper()
	c := &dns.Client{Net: "udp", Timeout: 1500 * time.Millisecond}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	resp, _, err := c.Exchange(q, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("unexpected resp: %#v", resp)
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A == nil {
		t.Fatalf("not an A record: %#v", resp.Answer[0])
	}
	return a.A.String()
}

// TestSmartDNSPool_EndToEnd builds the service from a real
// SmartDNSPoolServiceOptions, starts it, sends an A query to its bound
// address, and verifies the answer routed through one of the configured
// upstreams. This is the integration shape dnstt would use: resolver
// address = 127.0.0.1:<port> instead of 8.8.8.8:53.
func TestSmartDNSPool_EndToEnd(t *testing.T) {
	upA, stopA := startUDPUpstream(t, "192.0.2.51")
	defer stopA()
	upB, stopB := startUDPUpstream(t, "192.0.2.52")
	defer stopB()

	port := freePort(t)
	listenAddr := badoption.Addr{}
	if err := listenAddr.UnmarshalJSON([]byte(`"127.0.0.1"`)); err != nil {
		t.Fatalf("parse listen addr: %v", err)
	}

	opts := option.SmartDNSPoolServiceOptions{
		ListenOptions: option.ListenOptions{
			Listen:     &listenAddr,
			ListenPort: port,
		},
		Upstreams: []option.SmartDNSPoolUpstreamOptions{
			{Type: "udp", Address: upA},
			{Type: "udp", Address: upB},
		},
		LoadBalance: "roundrobin",
	}

	svc, err := NewService(context.Background(), log.NewNOPFactory().NewLogger("smart-dns-pool-test"), "smart-dns-pool", opts)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := svc.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer svc.Close()

	addr := "127.0.0.1:" + strconv.Itoa(int(port))

	// Wait for the listener to bind.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c := &dns.Client{Net: "udp", Timeout: 100 * time.Millisecond}
		q := new(dns.Msg)
		q.SetQuestion("ready.test.", dns.TypeA)
		if _, _, err := c.Exchange(q, addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Run several queries — round-robin should distribute across both upstreams.
	answers := map[string]int{}
	for i := 0; i < 10; i++ {
		ip := digOnce(t, addr, "smart.test.")
		answers[ip]++
	}
	if answers["192.0.2.51"] == 0 || answers["192.0.2.52"] == 0 {
		t.Fatalf("round-robin didn't reach both upstreams: %#v", answers)
	}
}

// TestSmartDNSPool_FailoverWithinDeadline configures one dropping upstream
// and one healthy one, and verifies queries through the local listener
// still get answered (the smart pool's failover keeps the tunnel alive
// even when one resolver is dead — the headline use case for dnstt).
func TestSmartDNSPool_FailoverWithinDeadline(t *testing.T) {
	// Dropping upstream: a UDP socket that just drops packets.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen drop: %v", err)
	}
	defer pc.Close()
	dropAddr := pc.LocalAddr().String()

	good, stopGood := startUDPUpstream(t, "192.0.2.60")
	defer stopGood()

	port := freePort(t)
	listenAddr := badoption.Addr{}
	if err := listenAddr.UnmarshalJSON([]byte(`"127.0.0.1"`)); err != nil {
		t.Fatalf("parse listen addr: %v", err)
	}

	opts := option.SmartDNSPoolServiceOptions{
		ListenOptions: option.ListenOptions{Listen: &listenAddr, ListenPort: port},
		Upstreams: []option.SmartDNSPoolUpstreamOptions{
			{Type: "udp", Address: dropAddr},
			{Type: "udp", Address: good},
		},
		Deadline:   badoption.Duration(2 * time.Second),
		PerAttempt: badoption.Duration(150 * time.Millisecond),
	}

	svc, err := NewService(context.Background(), log.NewNOPFactory().NewLogger("smart-dns-pool-test"), "smart-dns-pool", opts)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := svc.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer svc.Close()

	addr := "127.0.0.1:" + strconv.Itoa(int(port))
	// Warmup until the listener accepts.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c := &dns.Client{Net: "udp", Timeout: 100 * time.Millisecond}
		q := new(dns.Msg)
		q.SetQuestion("ready.test.", dns.TypeA)
		if _, _, err := c.Exchange(q, addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	saw := false
	for i := 0; i < 6; i++ {
		ip := digOnce(t, addr, "fail.test.")
		if ip == "192.0.2.60" {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("no successful answers — failover broken")
	}
}

// TestSmartDNSPool_RejectsBadConfig verifies validation at NewService time.
func TestSmartDNSPool_RejectsBadConfig(t *testing.T) {
	cases := []struct {
		name     string
		opts     option.SmartDNSPoolServiceOptions
		wantErr  string
		wantOK   bool
	}{
		{
			name: "no upstreams",
			opts: option.SmartDNSPoolServiceOptions{
				ListenOptions: option.ListenOptions{ListenPort: 19000},
			},
			wantErr: "at least one upstream is required",
		},
		{
			name: "missing port",
			opts: option.SmartDNSPoolServiceOptions{
				Upstreams: []option.SmartDNSPoolUpstreamOptions{
					{Type: "udp", Address: "1.1.1.1:53"},
				},
			},
			wantErr: "listen_port is required",
		},
		{
			name: "unsupported type",
			opts: option.SmartDNSPoolServiceOptions{
				ListenOptions: option.ListenOptions{ListenPort: 19000},
				Upstreams: []option.SmartDNSPoolUpstreamOptions{
					{Type: "h3", Address: "1.1.1.1:443"},
				},
			},
			wantErr: "unsupported upstream type",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewService(context.Background(), log.NewNOPFactory().NewLogger("test"), "t", tc.opts)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

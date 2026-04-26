package hmrd

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/miekg/dns"
)

// startEphemeralUDPServer spins up a tiny in-process UDP DNS server that
// answers any A query with 192.0.2.42. Returns "host:port" of the server
// and a stop function.
func startEphemeralUDPServer(t *testing.T) (string, func()) {
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
					A: net.IPv4(192, 0, 2, 42),
				})
			}
			_ = w.WriteMsg(r)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	return pc.LocalAddr().String(), func() { _ = srv.Shutdown() }
}

// TestHMRD_EndToEnd builds an "hmrd" sing-box transport from an options
// struct, points it at a real local upstream, runs Exchange, and verifies
// the response. This exercises the full adapter wiring: options → New →
// multidns.Manager → resolverState → upstream socket.
func TestHMRD_EndToEnd(t *testing.T) {
	addr, stop := startEphemeralUDPServer(t)
	defer stop()

	opts := option.HMRDDNSServerOptions{
		Upstreams: []option.HMRDUpstreamOptions{
			{Type: "udp", Address: addr},
		},
		LoadBalance:   "roundrobin",
		Deadline:      0, // pick library defaults
		PerAttempt:    0,
		ProbeInterval: 0,
		DownAfter:     0,
	}

	tr, err := New(context.Background(), log.NewNOPFactory().NewLogger("hmrd-test"), "hmrd-test", opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tr.Close()

	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := tr.Exchange(ctx, q)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected success, got %#v", resp)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(net.IPv4(192, 0, 2, 42)) {
		t.Fatalf("unexpected answer: %#v", resp.Answer[0])
	}

	if got := tr.Type(); got != "hmrd" {
		t.Fatalf("Type() = %q, want hmrd", got)
	}
	if got := tr.Tag(); got != "hmrd-test" {
		t.Fatalf("Tag() = %q, want hmrd-test", got)
	}
}

// TestHMRD_ProtocolMapping covers the type-string → multidns.Protocol
// translation for every alias the adapter accepts.
func TestHMRD_ProtocolMapping(t *testing.T) {
	cases := map[string]string{
		"udp":   "udp",
		"":      "udp", // empty defaults to UDP
		"tcp":   "tcp",
		"tls":   "dot",
		"dot":   "dot",
		"https": "doh",
		"doh":   "doh",
	}
	for in, want := range cases {
		got, err := parseProtocol(in)
		if err != nil {
			t.Fatalf("parseProtocol(%q): %v", in, err)
		}
		if string(got) != want {
			t.Fatalf("parseProtocol(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := parseProtocol("nope"); err == nil {
		t.Fatalf("expected error for unsupported type")
	}
}

// TestHMRD_RejectsEmptyUpstreams verifies the adapter refuses an options
// struct with no resolvers configured rather than silently building an
// unusable transport.
func TestHMRD_RejectsEmptyUpstreams(t *testing.T) {
	_, err := New(context.Background(), log.NewNOPFactory().NewLogger("hmrd-test"), "hmrd-test", option.HMRDDNSServerOptions{})
	if err == nil {
		t.Fatalf("expected error for empty upstreams")
	}
}

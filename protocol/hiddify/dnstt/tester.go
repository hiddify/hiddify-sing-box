package dnstt

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	dnstt "github.com/net2share/vaydns/client"
	"github.com/sagernet/sing-box/common/dnspool"
	"github.com/sagernet/sing/common/batch"

	"github.com/miekg/dns"
)

// historyKey names the saved resolver scores; each record type keeps its own.
func (h *Outbound) historyKey() string {
	return "dnstt_resolvers" + h.options.RecordType
}

func (h *Outbound) loadHistory() *dnspool.History {
	return dnspool.LoadHistory(h.cache, h.historyKey())
}

func (h *Outbound) saveHistory(his *dnspool.History) {
	his.Save(h.cache, h.historyKey(), h.logger)
}

func (h *Outbound) startTestResolver() error {
	history := h.loadHistory()
	defer h.saveHistory(history)

	b, _ := batch.New(h.ctx, batch.WithConcurrencyNum[any](100))

	// the shared order: built-in resolvers first, then by saved score, equals shuffled
	ordered := make([]dnspool.Candidate, len(h.candidateResolvers))
	byAddress := make(map[string]dnstt.Resolver, len(h.candidateResolvers))
	for i, r := range h.candidateResolvers {
		ordered[i] = dnspool.Candidate{Address: r.Resolver.ResolverAddr, Auto: r.Auto}
		byAddress[r.Resolver.ResolverAddr] = r.Resolver
	}
	history.Sort(ordered)

	for _, candidate := range ordered {
		resolver := byAddress[candidate.Address]

		select {
		case <-h.ctx.Done():
			return h.ctx.Err()
		default:
		}

		b.Go(resolver.ResolverAddr, func() (any, error) {
			h.mu.Lock()
			resCount := len(h.resolvers)
			h.mu.Unlock()
			if resCount > 10 {
				return nil, nil
			}

			// stop if context cancelled
			select {
			case <-h.ctx.Done():
				return nil, h.ctx.Err()
			default:
			}

			rate, err := h.testTunnelResolver(resolver)
			history.Record(resolver.ResolverAddr, rate)

			if err == nil {
				h.logger.InfoContext(h.ctx, "resolver ", resolver.ResolverAddr, " is working and added to the pool")
				h.addResolver(resolver)
				if h.isReady() {
					h.saveHistory(history)
				}
			} else {
				h.logger.WarnContext(h.ctx, "resolver ", resolver.ResolverAddr, " failed: ", err)
			}

			return nil, nil
		})
	}

	return b.Wait()
}
func (h *Outbound) testTunnelResolver(resolver dnstt.Resolver) (rate int, err error) {
	domain := h.options.PreTestDomain
	record := h.options.PreTestRecordType
	h.logger.DebugContext(h.ctx, "testing resolver ", resolver.ResolverAddr, " with domain ", domain, " and record type ", record)
	resp, err := h.Resolve(resolver, domain, dnspool.QueryType(record))
	h.logger.DebugContext(h.ctx, "resolver ", resolver.ResolverAddr, " response ", fmt.Sprint(resp), " error ", err)
	if err != nil {
		return -4, err
	}
	// ips := make([]string, 0)
	if resp == nil || len(resp.Answer) == 0 {
		return -3, fmt.Errorf("no record found in response from resolver %s", resolver.ResolverAddr)
	}
	// 	for _, ans := range resp.Answer {
	// 		if a, ok := ans.(*dns.A); ok {
	// 			if a.A.IsLoopback() || a.A.IsPrivate() {
	// 				continue
	// 			}
	// 			ips = append(ips, a.A.String())
	// 		}
	// 	}
	// }
	// if len(ips) == 0 {
	// 	return fmt.Errorf("no A record found in response from resolver %s", resolver.ResolverAddr)
	// }

	ctx, cancel := context.WithTimeout(h.ctx, 5*time.Second)
	defer cancel()
	tunnel, err := h.createDnsttTunnel(ctx, []dnstt.Resolver{resolver})
	if err != nil {
		h.logger.WarnContext(h.ctx, "failed to establish tunnel to resolver ", resolver.ResolverAddr, ": ", err)
		return -2, err
	}
	defer tunnel.Close()
	h.logger.InfoContext(h.ctx, "successfully established tunnel to resolver ", resolver.ResolverAddr)
	conn, err := tunnel.OpenStream()
	if err != nil {
		h.logger.WarnContext(h.ctx, "failed to open stream to resolver ", resolver.ResolverAddr, ": ", err)
		return -1, err

	}
	h.logger.InfoContext(h.ctx, "successfully opened stream to resolver ", resolver.ResolverAddr)
	conn.Close()
	return 1, nil

}

// ResolveUDP is the shared plain-DNS probe, through sing-box's UDP transport.
func (h *Outbound) ResolveUDP(resolver dnstt.Resolver, name string, qtype uint16) (*dns.Msg, error) {
	return dnspool.Probe(h.ctx, h.logger, resolver.ResolverAddr, name, qtype, h.options.DialerOptions)
}

func (h *Outbound) Resolve(resolver dnstt.Resolver, name string, qtype uint16) (*dns.Msg, error) {
	if resolver.ResolverType == dnstt.ResolverTypeUDP {
		return h.ResolveUDP(resolver, name, qtype)
	}
	conn, r, err := h.getTCPBasedResolverConnection(resolver, 5*time.Second)
	if err != nil { // the conn is nil on error
		return nil, err
	}
	defer conn.Close()                                     // one connection per resolver test
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second)) // a resolver that never answers must not block the test
	msg := dnspool.BuildQuery(name, qtype)

	data, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	_, err = conn.WriteTo(data, r)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)

	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, err
	}

	resp := new(dns.Msg)
	err = resp.Unpack(buf[:n])
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (h *Outbound) getTCPBasedResolverConnection(r dnstt.Resolver, timeout time.Duration) (net.PacketConn, *net.UDPAddr, error) {

	h.logger.InfoContext(h.ctx, "getting resolver connection ", r.ResolverAddr)
	switch r.ResolverType {
	case dnstt.ResolverTypeUDP:
		addr, err := net.ResolveUDPAddr("udp", r.ResolverAddr)
		if err != nil {
			return nil, nil, err
		}
		// t.remoteAddr = addr
		if r.UDPSharedSocket {
			lc := net.ListenConfig{Control: r.DialerControl}
			conn, err := lc.ListenPacket(context.Background(), "udp", ":0")
			if err != nil {
				return nil, nil, err
			}
			h.logger.InfoContext(h.ctx, "resolver connection established ", r.ResolverAddr)
			return conn, addr, nil
		} else {
			workers := r.UDPWorkers
			if workers <= 0 {
				workers = dnstt.DefaultUDPWorkers
			}

			if timeout <= 0 {
				timeout = dnstt.DefaultUDPResponseTimeout
			}
			conn, _, err := dnstt.NewUDPPacketConn(addr, r.DialerControl, workers, timeout, !r.UDPAcceptErrors, 512, "block")
			if err != nil {
				return nil, nil, err
			}
			h.logger.InfoContext(h.ctx, "resolver connection established ", r.ResolverAddr)
			// t.forgedStats = forgedStats
			return conn, addr, nil
		}

	case dnstt.ResolverTypeDOH:
		// t.remoteAddr = turbotunnel.DummyAddr{}
		var rt http.RoundTripper
		if r.RoundTripper != nil {
			rt = r.RoundTripper
		} else if r.UTLSClientHelloID != nil {
			rt = dnstt.NewUTLSRoundTripper(nil, r.UTLSClientHelloID)
		} else {
			rt = http.DefaultTransport
		}
		conn, err := dnstt.NewHTTPPacketConn(rt, r.ResolverAddr, 8, 512, "block")
		if err != nil {
			return nil, nil, err
		}
		return conn, nil, nil

	case dnstt.ResolverTypeDOT:
		// t.remoteAddr = turbotunnel.DummyAddr{}
		var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
		if r.UTLSClientHelloID != nil {
			id := r.UTLSClientHelloID
			dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dnstt.UTLSDialContext(ctx, network, addr, nil, id)
			}
		} else {
			dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.DialWithDialer(&net.Dialer{}, network, addr, nil)
			}
		}
		conn, err := dnstt.NewTLSPacketConn(r.ResolverAddr, dialTLSContext, 512, "block")
		if err != nil {
			return nil, nil, err
		}
		return conn, nil, nil

	default:
		return nil, nil, fmt.Errorf("unsupported resolver type: %s", r.ResolverType)
	}
}

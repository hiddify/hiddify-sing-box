package dnstt

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	dnstt "github.com/net2share/vaydns/client"
	"github.com/sagernet/sing-box/adapter"

	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/batch"

	"github.com/miekg/dns"
)

type History struct {
	ResolverRate map[string]int `json:"resolver_rate"`
}

func (h *Outbound) loadHistory() *History {
	history := &History{ResolverRate: make(map[string]int)}

	if h.cache == nil {
		return history
	}

	savedBinary := h.cache.LoadBinary("dnstt_resolvers" + h.options.RecordType)
	if savedBinary == nil {
		return history
	}
	if err := json.Unmarshal(savedBinary.Content, history); err != nil {
		return history
	}

	return history
}

func (h *Outbound) saveHistory(his *History) {
	if h.cache == nil {
		return
	}

	content, err := json.Marshal(his)
	if err != nil {
		h.logger.Error("failed to marshal outbound monitoring history: ", err)
		return
	}
	h.cache.SaveBinary("dnstt_resolvers"+h.options.RecordType, &adapter.SavedBinary{
		LastUpdated: time.Now(),
		Content:     content,
	})
}

func (h *Outbound) startTestResolver() error {
	history := h.loadHistory()
	defer h.saveHistory(history)

	b, _ := batch.New(h.ctx, batch.WithConcurrencyNum[any](100))

	candidates := h.candidateResolvers
	rand.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	})

	sort.Slice(candidates, func(i, j int) bool {
		a := candidates[i]
		b := candidates[j]

		// Auto first
		if a.Auto != b.Auto {
			return a.Auto
		}

		// Then by rate descending
		rateA := history.ResolverRate[a.Resolver.ResolverAddr]
		rateB := history.ResolverRate[b.Resolver.ResolverAddr]

		return rateA > rateB
	})
	historyMutex := sync.Mutex{}

	for _, r := range candidates {
		resolver := r.Resolver

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

			// update history safely
			historyMutex.Lock()
			defer historyMutex.Unlock()

			if err == nil {
				h.logger.InfoContext(h.ctx, "resolver ", resolver.ResolverAddr, " is working and added to the pool")

				if history.ResolverRate[resolver.ResolverAddr] < 0 {
					history.ResolverRate[resolver.ResolverAddr] = 0
				}
				history.ResolverRate[resolver.ResolverAddr] += rate
				if history.ResolverRate[resolver.ResolverAddr] > 10 {
					history.ResolverRate[resolver.ResolverAddr] = 10
				}

				h.addResolver(resolver)
				if h.IsReady() {
					h.saveHistory(history)
				}

			} else {
				h.logger.WarnContext(h.ctx, "resolver ", resolver.ResolverAddr, " failed: ", err)

				history.ResolverRate[resolver.ResolverAddr] += rate
				if history.ResolverRate[resolver.ResolverAddr] < -10 {
					history.ResolverRate[resolver.ResolverAddr] = -10
				}
			}

			return nil, nil
		})
	}

	return b.Wait()
}
func getDnsRecordType(record string) uint16 {
	switch record {
	case "a":
		return dns.TypeA
	case "aaaa":
		return dns.TypeAAAA
	case "cname":
		return dns.TypeCNAME
	case "mx":
		return dns.TypeMX
	case "ns":
		return dns.TypeNS
	case "ptr":
		return dns.TypePTR
	case "soa":
		return dns.TypeSOA
	case "srv":
		return dns.TypeSRV
	case "txt":
		return dns.TypeTXT
	default:
		return dns.TypeA
	}
}

func (h *Outbound) testTunnelResolver(resolver dnstt.Resolver) (rate int, err error) {
	domain := h.options.PreTestDomain
	record := h.options.PreTestRecordType
	h.logger.DebugContext(h.ctx, "testing resolver ", resolver.ResolverAddr, " with domain ", domain, " and record type ", record)
	resp, err := h.Resolve(resolver, domain, getDnsRecordType(record))
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

func buildDNSQuery(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true

	return m
}

func (h *Outbound) ResolveUDP(resolver dnstt.Resolver, name string, qtype uint16) (*dns.Msg, error) {
	host, portStr, err := net.SplitHostPort(resolver.ResolverAddr)
	if err != nil {
		return nil, err
	}

	portInt, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	trans, err := transport.NewUDP(
		h.ctx,
		h.logger,
		"resolver"+resolver.ResolverAddr,
		option.RemoteDNSServerOptions{
			DNSServerAddressOptions: option.DNSServerAddressOptions{
				Server:     host,
				ServerPort: uint16(portInt),
			},
		},
	)
	if err != nil {
		return nil, err
	}
	// h.logger.InfoContext(h.ctx, "resolving name ", name, " of type ", qtype, " using resolver ", resolver.ResolverAddr)

	msg := buildDNSQuery(name, qtype)
	trans.Start(adapter.StartStateStart)
	ctx, cancel := context.WithTimeout(h.ctx, 5*time.Second)
	defer cancel()
	resp, err := trans.Exchange(ctx, msg)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (h *Outbound) Resolve(resolver dnstt.Resolver, name string, qtype uint16) (*dns.Msg, error) {
	if resolver.ResolverType == dnstt.ResolverTypeUDP {
		return h.ResolveUDP(resolver, name, qtype)
	}
	conn, r, err := h.getTCPBasedResolverConnection(resolver, 5*time.Second)
	msg := buildDNSQuery(name, qtype)

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

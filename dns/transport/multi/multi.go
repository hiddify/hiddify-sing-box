package multi

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
)

func RegisterTransport(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.MultiDNSServerOptions](registry, C.DNSTypeMulti, NewTransport)
}

var _ adapter.DNSTransport = (*Transport)(nil)

type Transport struct {
	dns.TransportAdapter
	serverTags    []string
	parallel      bool
	transports    []adapter.DNSTransport
	manager       adapter.DNSTransportManager
	ignoredRanges []netip.Prefix
	done          chan struct{}
	logger        log.ContextLogger
}

func NewTransport(ctx context.Context, logger log.ContextLogger, tag string, options option.MultiDNSServerOptions) (adapter.DNSTransport, error) {
	ignoreRanges := make([]netip.Prefix, 0, len(options.IgnoreRanges))
	for _, r := range options.IgnoreRanges {
		ignoreRanges = append(ignoreRanges, netip.Prefix(r))
	}

	return &Transport{
		TransportAdapter: dns.NewTransportAdapter(C.DNSTypeMulti, tag, options.Servers),
		manager:          service.FromContext[adapter.DNSTransportManager](ctx),
		serverTags:       options.Servers,
		parallel:         options.Parallel,
		ignoredRanges:    ignoreRanges,
		done:             make(chan struct{}),
		logger:           logger,
	}, nil
}

func (m *Transport) Start(stage adapter.StartStage) error {
	if stage == adapter.StartStateStart {
		for _, tag := range m.serverTags {
			transport, found := m.manager.Transport(tag)
			if !found {
				return E.New("dns transport not found: ", tag)
			}
			m.transports = append(m.transports, transport)
		}
	}
	return nil
}

func (t *Transport) Close() error {
	t.logger.Debug("closing multi dns transport ", t.Tag())
	close(t.done)
	return nil
}

func (t *Transport) Reset() {
}

func (m *Transport) Exchange(ctx context.Context, msg *mDNS.Msg) (*mDNS.Msg, error) {
	defer func() {
		select {
		case <-m.done:
			m.logger.Debug("m done closing multi dns transport successfully ", m.Tag())
		case <-ctx.Done():
			m.logger.Debug("ctx done, closing multi dns transport successfully ", m.Tag(), " ctx error: ", ctx.Err())
		default:
		}
	}()
	if len(m.transports) == 0 {
		return nil, E.New("no dns transports configured")
	}

	if !m.parallel {
		return m.exchangeSerial(ctx, msg)
	}

	return m.exchangeParallel(ctx, msg)
}
func (m *Transport) exchangeSerial(parent context.Context, msg *mDNS.Msg) (*mDNS.Msg, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	var lastErr error
	var lastResp *mDNS.Msg
	for _, tr := range m.transports {
		select {
		case <-m.done:
			return nil, E.New("transport closed")
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		resp, err := tr.Exchange(ctx, msg)
		if err != nil {
			lastErr = err
			continue
		}
		var change bool
		resp, change = m.filterBlocked(resp)
		if len(resp.Answer) > 0 {
			return resp, nil
		}
		if !change {
			lastResp = resp
		}
	}

	if lastResp != nil {
		return lastResp, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, E.New("no dns response")
}
func (m *Transport) exchangeParallel(parent context.Context, msg *mDNS.Msg) (*mDNS.Msg, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()

	type result struct {
		resp *mDNS.Msg
		err  error
	}

	results := make(chan result, len(m.transports))

	var wg sync.WaitGroup
	wg.Add(len(m.transports))

	for _, tr := range m.transports {
		go func(tr adapter.DNSTransport) {
			defer wg.Done()

			resp, err := tr.Exchange(ctx, msg)
			select {
			case results <- result{resp: resp, err: err}:
			case <-ctx.Done():
			case <-m.done:
			}
		}(tr)
	}

	// Close results exactly once
	go func() {
		wg.Wait()
		close(results)

	}()

	var lastErr error
	var lastResp *mDNS.Msg

	for {
		select {
		case r, ok := <-results:
			if !ok {
				m.logger.Trace("all transports completed, no response received")
				if lastResp != nil {
					return lastResp, nil
				}
				if lastErr != nil {
					return nil, lastErr
				}
				return nil, E.New("no dns response")
			}
			if r.err != nil {
				lastErr = r.err
				continue
			}
			resp, change := m.filterBlocked(r.resp)
			if len(resp.Answer) > 0 {
				cancel() // stop others
				return resp, nil
			}
			if !change {
				lastResp = resp
			}
		case <-m.done:
			return nil, E.New("transport closed")
		case <-ctx.Done():
			if lastResp != nil {
				return lastResp, nil
			}
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, ctx.Err()
		}
	}
}

func (m *Transport) filterBlocked(msg *mDNS.Msg) (*mDNS.Msg, bool) {
	if msg == nil {
		return nil, false
	}
	if len(msg.Answer) == 0 {
		return msg, false
	}
	answers := make([]mDNS.RR, 0)
	for _, r := range msg.Answer {
		switch answer := r.(type) {
		case *mDNS.A:
			if m.isBlocked(answer.A) {
				continue
			}
		case *mDNS.AAAA:
			if m.isBlocked(answer.AAAA) {
				continue
			}
		default:
		}
		answers = append(answers, r)
	}
	hasChanged := len(answers) != len(msg.Answer)
	msg.Answer = answers
	return msg, hasChanged
}

func (m *Transport) isBlocked(ip net.IP) bool {
	netipAddr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	if !netipAddr.IsValid() {
		return true
	}

	for _, p := range m.ignoredRanges {
		if p.Contains(netipAddr) {
			return true
		}
	}
	return false
}

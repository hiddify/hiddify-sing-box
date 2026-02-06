package multi

import (
	"context"
	"net"
	"net/netip"

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
	return nil
}

func (t *Transport) Reset() {
}

func (m *Transport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	callback(m.Exchange(ctx, message))
}

func (m *Transport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	lastErr := E.New("No transports failed")
	var lastResponse *mDNS.Msg
	if m.parallel {
		resch := make(chan *mDNS.Msg, len(m.transports))
		errch := make(chan error, len(m.transports))

		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		for _, tr := range m.transports {
			go func(tr adapter.DNSTransport) {
				//fmt.Println("sending to ", tr.Tag(), " with message ", message)
				r, err := tr.Exchange(ctx, message)
				//fmt.Println("received from ", tr.Tag(), " with response ", r, " and error ", err)
				if err != nil {
					errch <- err
					return
				}

				select {
				case resch <- r:
				case <-ctx.Done():
				}
			}(tr)
		}
		for i := 0; i < len(m.transports); i++ {
			select {
			case response := <-resch:
				response = m.filterBlocked(ctx, response)
				if len(response.Answer) > 0 {
					cancel()
					//fmt.Println("responding with ", response.Rcode, " and ", len(response.Answer), " answers ", response)
					return response, nil
				}
				lastResponse = response
			case err := <-errch:
				lastErr = err
			}
		}

	} else {
		for _, tr := range m.transports {
			//fmt.Println("sending to ", tr.Tag(), " with message ", message)
			response, err := tr.Exchange(ctx, message)
			//fmt.Println("received from ", tr.Tag(), " with response ", response, " and error ", err)
			if err != nil {
				lastErr = err
				continue
			}

			response = m.filterBlocked(ctx, response)
			if len(response.Answer) > 0 {
				//fmt.Println("responding with ", response.Rcode, " and ", len(response.Answer), " answers ", response)
				return response, nil
			}
			lastResponse = response

		}
	}

	if lastResponse != nil {
		//fmt.Println("No SUCCESS! responding with ", lastResponse.Rcode, " and ", len(lastResponse.Answer), " answers ", lastResponse)
		return lastResponse, nil
	}
	//fmt.Println("all transports Error, ", lastErr)
	return nil, lastErr

}

func (m *Transport) filterBlocked(ctx context.Context, msg *mDNS.Msg) *mDNS.Msg {
	if msg == nil {
		return nil
	}
	if len(msg.Answer) == 0 {
		return msg
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
	msg.Answer = answers
	return msg
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

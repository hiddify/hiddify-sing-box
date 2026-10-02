package transport

import (
	"context"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

var _ adapter.DNSTransport = (*GroupTransport)(nil)

func RegisterGroup(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.GroupDNSServerOptions](registry, C.DNSTypeGroup, NewGroup)
}

// RegisterMulti keeps the deprecated "multi" type working on top of the group transport.
func RegisterMulti(registry *dns.TransportRegistry) { //H
	dns.RegisterTransport[option.MultiDNSServerOptions](registry, C.DNSTypeMulti, NewMulti)
}

type GroupTransport struct {
	dns.TransportAdapter

	ctx          context.Context
	logger       log.ContextLogger
	serverTags   []string
	sequential   bool           //H
	ignoreRanges []netip.Prefix //H
}

func NewGroup(ctx context.Context, logger log.ContextLogger, tag string, options option.GroupDNSServerOptions) (adapter.DNSTransport, error) {
	return newGroup(ctx, logger, C.DNSTypeGroup, tag, options)
}

func NewMulti(ctx context.Context, logger log.ContextLogger, tag string, options option.MultiDNSServerOptions) (adapter.DNSTransport, error) { //H
	logger.Warn("DNS server type `multi` is deprecated, use `group` with `mode` instead")
	mode := C.DNSGroupModeSequential
	if options.Parallel {
		mode = C.DNSGroupModeParallel
	}
	return newGroup(ctx, logger, C.DNSTypeMulti, tag, option.GroupDNSServerOptions{
		Servers:      options.Servers,
		Mode:         mode,
		IgnoreRanges: options.IgnoreRanges,
	})
}

func newGroup(ctx context.Context, logger log.ContextLogger, transportType string, tag string, options option.GroupDNSServerOptions) (adapter.DNSTransport, error) {
	if len(options.Servers) == 0 {
		return nil, E.New("missing servers")
	}
	var sequential bool
	switch options.Mode {
	case "", C.DNSGroupModeParallel:
	case C.DNSGroupModeSequential:
		sequential = true
	default:
		return nil, E.New("unknown group mode: ", options.Mode)
	}
	ignoreRanges := make([]netip.Prefix, 0, len(options.IgnoreRanges))
	for _, prefix := range options.IgnoreRanges {
		ignoreRanges = append(ignoreRanges, netip.Prefix(prefix))
	}
	return &GroupTransport{
		TransportAdapter: dns.NewTransportAdapter(transportType, tag, options.Servers),
		ctx:              ctx,
		logger:           logger,
		serverTags:       options.Servers,
		sequential:       sequential,
		ignoreRanges:     ignoreRanges,
	}, nil
}

func (t *GroupTransport) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	transportManager := service.FromContext[adapter.DNSTransportManager](t.ctx)
	if transportManager == nil {
		return E.New("missing DNS transport manager")
	}
	for _, tag := range t.serverTags {
		transport, loaded := transportManager.Transport(tag)
		if !loaded {
			return E.New("DNS server not found: ", tag)
		}
		if transport.Type() == C.DNSTypeGroup || transport.Type() == C.DNSTypeMulti {
			return E.New("group cannot contain another group: ", tag)
		}
		if transport.Type() == C.DNSTypeFakeIP {
			return E.New("group cannot contain fakeip server: ", tag)
		}
	}
	return nil
}

func (t *GroupTransport) Close() error {
	return nil
}

func (t *GroupTransport) Reset() {
}

func (t *GroupTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	done := make(chan struct{})
	var (
		response *mDNS.Msg
		err      error
	)
	t.ExchangeAsync(ctx, message, func(callbackResponse *mDNS.Msg, callbackErr error) {
		response = callbackResponse
		err = callbackErr
		close(done)
	})
	<-done
	return response, err
}

type groupResult struct {
	response *mDNS.Msg
	tag      string
	err      error
}

// A response is accepted once it still has answers after ignore_ranges
// filtering. An empty response is kept only as a fallback, unless filtering
// emptied it, so a fast poisoned or blocked reply cannot win.
type groupCollector struct {
	transport *GroupTransport
	fallback  *mDNS.Msg
	err       error
}

func (c *groupCollector) add(ctx context.Context, r groupResult, keepFirstErr bool) (*mDNS.Msg, bool) {
	if r.err == nil && r.response == nil {
		r.err = E.New("empty response from ", r.tag)
	}
	if r.err != nil {
		if c.err == nil || !keepFirstErr {
			c.err = r.err
		}
		return nil, false
	}
	response, filtered := c.transport.filterIgnored(r.response)
	if len(response.Answer) > 0 {
		c.transport.logger.DebugContext(ctx, "response from ", r.tag)
		return response, true
	}
	if filtered {
		c.transport.logger.DebugContext(ctx, "ignored response from ", r.tag)
	} else if c.fallback == nil {
		c.fallback = response
	}
	return nil, false
}

func (c *groupCollector) finish() (*mDNS.Msg, error) {
	if c.fallback != nil {
		return c.fallback, nil
	}
	if c.err != nil {
		return nil, c.err
	}
	return nil, E.New("all DNS servers failed")
}

func (t *GroupTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	transportManager := service.FromContext[adapter.DNSTransportManager](t.ctx)
	if transportManager == nil {
		callback(nil, E.New("missing DNS transport manager"))
		return
	}
	if t.sequential {
		go t.exchangeSequential(ctx, transportManager, message, callback)
		return
	}
	t.exchangeParallel(ctx, transportManager, message, callback)
}

func (t *GroupTransport) exchangeSequential(ctx context.Context, transportManager adapter.DNSTransportManager, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) { //H
	collector := groupCollector{transport: t}
	for _, tag := range t.serverTags {
		transport, loaded := transportManager.Transport(tag)
		if !loaded {
			collector.add(ctx, groupResult{nil, tag, E.New("DNS server not found: ", tag)}, false)
			continue
		}
		resultCh := make(chan groupResult, 1)
		childContext, cancel := context.WithCancel(adapter.OverrideContext(ctx))
		transport.ExchangeAsync(childContext, message.Copy(), func(response *mDNS.Msg, err error) {
			resultCh <- groupResult{response, tag, err}
		})
		var r groupResult
		select {
		case <-ctx.Done():
			cancel()
			if collector.fallback != nil {
				callback(collector.fallback, nil)
			} else {
				callback(nil, ctx.Err())
			}
			return
		case r = <-resultCh:
		}
		cancel()
		if response, accepted := collector.add(ctx, r, false); accepted {
			callback(response, nil)
			return
		}
	}
	callback(collector.finish())
}

func (t *GroupTransport) exchangeParallel(ctx context.Context, transportManager adapter.DNSTransportManager, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	resultCh := make(chan groupResult, len(t.serverTags))
	ctx, cancel := context.WithCancel(ctx)

	for _, tag := range t.serverTags {
		transport, loaded := transportManager.Transport(tag)
		if !loaded {
			resultCh <- groupResult{nil, tag, E.New("DNS server not found: ", tag)}
			continue
		}
		childContext := adapter.OverrideContext(ctx)
		childMessage := message.Copy()
		go transport.ExchangeAsync(childContext, childMessage, func(response *mDNS.Msg, err error) {
			resultCh <- groupResult{response, tag, err}
		})
	}

	go func() {
		defer cancel()
		collector := groupCollector{transport: t}
		for range t.serverTags {
			var r groupResult
			select {
			case <-ctx.Done():
				if collector.fallback != nil {
					callback(collector.fallback, nil)
				} else {
					callback(nil, ctx.Err())
				}
				return
			case r = <-resultCh:
			}
			if response, accepted := collector.add(ctx, r, true); accepted {
				cancel()
				callback(response, nil)
				return
			}
		}
		callback(collector.finish())
	}()
}

// filterIgnored drops A/AAAA records inside ignore_ranges. The input message
// is never modified.
func (t *GroupTransport) filterIgnored(message *mDNS.Msg) (*mDNS.Msg, bool) { //H
	if len(t.ignoreRanges) == 0 || len(message.Answer) == 0 {
		return message, false
	}
	answers := make([]mDNS.RR, 0, len(message.Answer))
	for _, record := range message.Answer {
		switch answer := record.(type) {
		case *mDNS.A:
			if t.isIgnored(answer.A) {
				continue
			}
		case *mDNS.AAAA:
			if t.isIgnored(answer.AAAA) {
				continue
			}
		}
		answers = append(answers, record)
	}
	if len(answers) == len(message.Answer) {
		return message, false
	}
	filtered := message.Copy()
	filtered.Answer = answers
	return filtered, true
}

func (t *GroupTransport) isIgnored(ip net.IP) bool { //H
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	address = address.Unmap()
	for _, prefix := range t.ignoreRanges {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

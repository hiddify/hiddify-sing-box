package dnstt

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	dnstt "github.com/net2share/vaydns/client"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.DnsttOptions](registry, C.TypeDNSTT, NewOutbound)
	loadResolvers()
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	dnsRouter adapter.DNSRouter
	logger    logger.ContextLogger
	ctx       context.Context

	candidateResolvers []ResolverS
	resolvers          []dnstt.Resolver
	tunnels            []*dnstt.Tunnel
	mutlitunnel        *dnstt.Tunnel
	mu                 sync.Mutex
	cache              adapter.CacheFile
	uotClient          *uot.Client
	started            int
	resolve            bool
	tunnel_index       int

	options option.DnsttOptions
}

func (c *Outbound) PreStart() error {
	c.cache = service.FromContext[adapter.CacheFile](c.ctx)
	return nil
}

func (h *Outbound) PostStart() error {
	go h.startTestResolver()
	return nil
}

func initDuration(d *badoption.Duration, defultDuration time.Duration) time.Duration {
	b := d.Build()
	if b <= 0 {
		return defultDuration
	}
	return b
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DnsttOptions) (adapter.Outbound, error) {

	// if options.TunnelPerResolver <= 0 {
	// 	options.TunnelPerResolver = 4
	// }

	resolvers, err := getConfigResolvers(options)
	if err != nil {
		return nil, err
	}

	if len(resolvers) == 0 {
		return nil, E.New("at least one resolver is required")
	}
	if options.RecordType == "" {
		options.RecordType = "txt"
	}
	if options.PublicKey == "" {
		return nil, E.New("public key is required")
	}

	if options.Domain == "" {
		return nil, E.New("domain is required")
	}
	if options.PreTestRecordType == "" {
		options.PreTestRecordType = "a"
	}
	if options.PreTestDomain == "" {
		options.PreTestDomain = "www.google.com"
	}

	out := &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeDNSTT, tag, []string{N.NetworkTCP}, options.DialerOptions),
		ctx:     ctx,
		logger:  logger,

		candidateResolvers: resolvers,
		resolvers:          make([]dnstt.Resolver, 0),
		tunnels:            make([]*dnstt.Tunnel, 0),

		options: options,
	}

	return out, nil

}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !h.IsReady() {
		return nil, E.New("outbound is not started")
	}
	if h.options.SingleResolver {
		return h.OpenStreamSingleResolver(ctx)
	}
	return h.OpenStream(ctx)
}
func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !h.IsReady() {
		return nil, E.New("outbound is not started")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	if h.uotClient != nil {
		h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		return h.uotClient.ListenPacket(ctx, destination)
	}
	return nil, E.New("UoT is not enabled for this outbound")
}

func (c *Outbound) IsReady() bool {
	return c.started > 0
}
func (w *Outbound) DisplayType() string {
	str := C.ProxyDisplayName(w.Type())
	if w.started == 0 {
		str += " ⚠️ Connecting..."
	} else if w.started < 0 {
		str += " ❌ Failed!"
	} else {
		str += fmt.Sprint(" ✔️ ", len(w.resolvers), " resolvers")
	}
	return str
}

func (c *Outbound) Close() error {
	for _, t := range c.tunnels {
		if t != nil {
			t.Close()
		}
	}
	return nil
}

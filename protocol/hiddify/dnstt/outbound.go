package dnstt

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"

	dnstt "github.com/mahsanet/dnstt/client"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.DnsttOptions](registry, C.TypeDNSTT, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	dnsRouter adapter.DNSRouter
	logger    logger.ContextLogger
	ctx       context.Context

	resolvers    []dnstt.Resolver
	publicKey    string
	domain       string
	tunnels      []*dnstt.Tunnel
	tunnel_index int
	mu           sync.Mutex

	uotClient *uot.Client
	resolve   bool
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DnsttOptions) (adapter.Outbound, error) {
	resolvers := []dnstt.Resolver{}
	if options.TunnelPerResolver <= 0 {
		options.TunnelPerResolver = 4
	}
	for _, resolverAddr := range options.Resolvers {
		resolver, err := dnstt.NewResolver(dnstt.ResolverTypeUDP, resolverAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid resolver address %s: %w", resolverAddr, err)
		}
		for i := 0; i < options.TunnelPerResolver; i++ {
			resolvers = append(resolvers, resolver)
		}
	}

	if len(resolvers) == 0 {
		return nil, E.New("at least one resolver is required")
	}

	if options.PublicKey == "" {
		return nil, E.New("public key is required")
	}

	if options.Domain == "" {
		return nil, E.New("domain is required")
	}
	return &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(C.TypeSOCKS, tag, options.Network.Build(), options.DialerOptions),
		ctx:       ctx,
		logger:    logger,
		domain:    options.Domain,
		publicKey: options.PublicKey,
		resolvers: resolvers,
		tunnels:   make([]*dnstt.Tunnel, len(resolvers)),
	}, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	tunnel, err := h.establishDnsttTunnel(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get or establish tunnel: %w", err)
	}

	stream, err := tunnel.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}

	return &LoggingConn{Conn: stream, outbound: h, tunnel_index: h.tunnel_index}, nil
	// return stream, nil
}

type LoggingConn struct {
	net.Conn
	rx           bytes.Buffer
	tx           bytes.Buffer
	outbound     *Outbound
	tunnel_index int
}

func (c *LoggingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.rx.Write(b[:n])
	}
	return n, err
}

func (c *LoggingConn) Write(b []byte) (int, error) {
	if len(b) > 0 {
		c.tx.Write(b)
	}
	return c.Conn.Write(b)
}

func (c *LoggingConn) Close() error {
	c.outbound.logger.Info(c.outbound.Tag(), " Tunnel ", c.tunnel_index, " closing connection. TX bytes: ", c.tx.Len(), ", RX bytes: ", c.rx.Len())
	// bs := c.rx.Bytes()

	// fmt.Printf("TX bytes: \n%s\n", c.tx.String())
	// if len(bs) > 0 {
	// 	fmt.Printf("RX bytes: \n%s\n", c.tx.String())
	// } else {
	// 	fmt.Printf("RX bytes: %d \n", len(bs))
	// }
	return c.Conn.Close()
}
func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	if h.uotClient != nil {
		h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		return h.uotClient.ListenPacket(ctx, destination)
	}
	return nil, E.New("UoT is not enabled for this outbound")
}

func (c *Outbound) Close() error {
	for _, t := range c.tunnels {
		if t != nil {
			t.Close()
		}
	}
	return nil
}

func (c *Outbound) establishDnsttTunnel(ctx context.Context) (*dnstt.Tunnel, error) {
	// dnsttConfig := streamSettings.ProtocolSettings.(*Config)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tunnel_index = (c.tunnel_index + 1) % len(c.resolvers)
	if c.tunnels[c.tunnel_index] != nil {
		return c.tunnels[c.tunnel_index], nil
	}
	tServer, err := dnstt.NewTunnelServer(c.domain, c.publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid tunnel server: %w", err)
	}

	resolver := c.resolvers[c.tunnel_index]

	tunnel, err := dnstt.NewTunnel(resolver, tServer)
	if err != nil {
		return nil, fmt.Errorf("failed to create tunnel: %w", err)
	}

	if err := tunnel.InitiateResolverConnection(); err != nil {
		return nil, fmt.Errorf("failed to initiate connection to resolver: %w", err)
	}

	if err := tunnel.InitiateDNSPacketConn(tServer.Addr); err != nil {
		return nil, fmt.Errorf("failed to initiate DNS packet connection: %w", err)
	}

	c.logger.Debug("effective MTU %d", tServer.MTU)

	if err := tunnel.InitiateKCPConn(tServer.MTU); err != nil {
		return nil, fmt.Errorf("failed to initiate KCP connection: %w", err)
	}

	c.logger.Debug("established KCP conn")

	if err := tunnel.InitiateNoiseChannel(); err != nil {
		c.logger.Warn("failed to establish Noise channel: %v", err)
		return nil, fmt.Errorf("failed to initiate Noise channel: %w", err)
	}

	c.logger.Debug("established Noise channel")

	if err := tunnel.InitiateSmuxSession(); err != nil {
		return nil, fmt.Errorf("failed to initiate smux session: %w", err)
	}

	c.tunnels[c.tunnel_index] = tunnel
	c.logger.InfoContext(ctx, "tunnel [", c.tunnel_index, "] ", c.Tag(), "resolver ", resolver.ResolverAddr)

	c.logger.Debug("established smux session")
	return tunnel, nil
}

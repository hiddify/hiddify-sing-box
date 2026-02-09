package v2raydnstt

import (
	"context"
	"sync"

	"github.com/sagernet/sing-box/common/tls"

	"fmt"
	"log"
	"net"

	dnstt "github.com/mahsanet/dnstt/client"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

type Client struct {
	ctx       context.Context
	dialer    N.Dialer
	resolvers []dnstt.Resolver
	publicKey string
	domain    string
	tunnel    *dnstt.Tunnel
	mu        sync.Mutex
}

// Close implements [adapter.V2RayClientTransport].
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tunnel == nil {
		return nil
	}
	err := c.tunnel.Close()
	c.tunnel = nil
	return err
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.DnsttOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	resolvers := []dnstt.Resolver{}
	for _, resolverAddr := range options.Resolvers {
		resolver, err := dnstt.NewResolver(dnstt.ResolverTypeUDP, resolverAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid resolver address %s: %w", resolverAddr, err)
		}
		resolvers = append(resolvers, resolver)
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
	return &Client{
		ctx:       ctx,
		dialer:    dialer,
		domain:    options.Domain,
		publicKey: options.PublicKey,
		resolvers: resolvers,
	}, nil
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {

	tunnel, err := c.establishDnsttTunnel(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get or establish tunnel: %w", err)
	}

	stream, err := tunnel.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}

	return stream, nil
}

func (c *Client) establishDnsttTunnel(ctx context.Context) (*dnstt.Tunnel, error) {
	// dnsttConfig := streamSettings.ProtocolSettings.(*Config)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tunnel != nil {
		return c.tunnel, nil
	}
	tServer, err := dnstt.NewTunnelServer(c.domain, c.publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid tunnel server: %w", err)
	}

	tunnelServers := []dnstt.TunnelServer{tServer}

	resolver := c.resolvers[0]
	tunnelServer := tunnelServers[0]

	tunnel, err := dnstt.NewTunnel(resolver, tunnelServer)
	if err != nil {
		return nil, fmt.Errorf("failed to create tunnel: %w", err)
	}

	if err := tunnel.InitiateResolverConnection(); err != nil {
		return nil, fmt.Errorf("failed to initiate connection to resolver: %w", err)
	}

	if err := tunnel.InitiateDNSPacketConn(tunnelServer.Addr); err != nil {
		return nil, fmt.Errorf("failed to initiate DNS packet connection: %w", err)
	}

	log.Printf("effective MTU %d", tunnelServer.MTU)

	if err := tunnel.InitiateKCPConn(tunnelServer.MTU); err != nil {
		return nil, fmt.Errorf("failed to initiate KCP connection: %w", err)
	}

	log.Printf("established KCP conn")

	if err := tunnel.InitiateNoiseChannel(); err != nil {
		log.Printf("failed to establish Noise channel: %v", err)
		return nil, fmt.Errorf("failed to initiate Noise channel: %w", err)
	}

	log.Printf("established Noise channel")

	if err := tunnel.InitiateSmuxSession(); err != nil {
		return nil, fmt.Errorf("failed to initiate smux session: %w", err)
	}

	c.tunnel = tunnel
	log.Printf("established smux session")
	return tunnel, nil
}

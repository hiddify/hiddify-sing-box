package dnstt

import (
	"context"
	"math/rand"
	"net"

	"fmt"

	dnstt "github.com/net2share/vaydns/client"
	"github.com/sagernet/sing-box/common/monitoring"
)

func (c *Outbound) addResolver(resolver dnstt.Resolver) {
	c.mu.Lock()
	// for i := 0; i < c.options.TunnelPerResolver; i++ {
	c.resolvers = append(c.resolvers, resolver)
	c.tunnels = append(c.tunnels, nil)
	c.mutlitunnel = nil
	// }
	c.mu.Unlock()
	if !c.IsReady() {
		c.started = 1
		c.logger.InfoContext(c.ctx, "initial resolver ", resolver.ResolverAddr)
		monitoring.Get(c.ctx).TestNow(c.Tag())
	}

}

func (c *Outbound) openStreamImp(ctx context.Context) (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t := c.mutlitunnel; t != nil {
		return t.OpenStream()
	}

	if newtunnel, err := c.createDnsttTunnel(ctx, c.resolvers); err != nil {
		return nil, err
	} else {
		c.mutlitunnel = newtunnel
		return newtunnel.OpenStream()
	}
}
func (c *Outbound) OpenStream(ctx context.Context) (net.Conn, error) {
	var err error
	var conn net.Conn
	for range 3 {
		conn, err = c.openStreamImp(ctx)
		if err == nil {
			return conn, nil
		}
	}
	return nil, err
}
func (c *Outbound) OpenStreamSingleResolver(ctx context.Context) (net.Conn, error) {
	// dnsttConfig := streamSettings.ProtocolSettings.(*Config)
	c.mu.Lock()
	defer c.mu.Unlock()
	// c.tunnel_index = (c.tunnel_index + 1) % len(c.tunnels)
	var lasterr error
	for i := 0; i < max(5, len(c.tunnels)); i++ {
		tunnel_index := rand.Intn(len(c.resolvers)) // 0 <= x < n
		tunnel := c.tunnels[tunnel_index]
		if tunnel == nil {
			if newtunnel, err := c.createDnsttTunnel(ctx, []dnstt.Resolver{c.resolvers[tunnel_index]}); err != nil {
				lasterr = err
				c.logger.DebugContext(ctx, "tunnel [", tunnel_index, "]  failed resolver ", c.resolvers[tunnel_index].ResolverAddr)
			} else {
				c.tunnels[tunnel_index] = newtunnel
				tunnel = newtunnel
				c.logger.InfoContext(ctx, "tunnel [", tunnel_index, "] resolver ", c.resolvers[tunnel_index].ResolverAddr)

				// return tunnel, nil
			}
		}
		if tunnel != nil {
			if conn, err := tunnel.OpenStream(); err == nil {
				// return &LoggingConn{Conn: stream, outbound: h, tunnel_index: h.tunnel_index}, nil
				return conn, nil
			} else {
				lasterr = err
			}
			tunnel.Close()
			c.tunnels[tunnel_index] = nil
		}
	}
	return nil, lasterr
}
func (c *Outbound) createDnsttTunnel(ctx context.Context, resolver []dnstt.Resolver) (*dnstt.Tunnel, error) {
	tServer, err := dnstt.NewTunnelServer(c.options.Domain, c.options.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid tunnel server: %w", err)
	}

	if c.options.MTU != nil {
		tServer.MTU = *c.options.MTU
	}

	tServer.DnsttCompat = c.options.DnsttCompat

	if c.options.ClientIDSize != nil {
		tServer.ClientIDSize = *c.options.ClientIDSize
	}

	if c.options.MaxNumLabels != nil {
		tServer.MaxNumLabels = *c.options.MaxNumLabels
	}
	if c.options.RPS != nil {
		tServer.RPS = *c.options.RPS
	}
	if c.options.MaxQnameLen != nil {
		tServer.MaxQnameLen = *c.options.MaxQnameLen
	}

	tunnel, err := dnstt.NewTunnel(resolver, tServer)
	if err != nil {
		return nil, fmt.Errorf("failed to create tunnel: %w", err)
	}
	if c.options.OpenStreamTimeout != nil {
		tunnel.OpenStreamTimeout = c.options.OpenStreamTimeout.Build()
	}
	if c.options.MaxStreams != nil {
		tunnel.MaxStreams = *c.options.MaxStreams
	}
	if c.options.ReconnectMinDelay != nil {
		tunnel.ReconnectMinDelay = c.options.ReconnectMinDelay.Build()
	}
	if c.options.ReconnectMaxDelay != nil {
		tunnel.ReconnectMaxDelay = c.options.ReconnectMaxDelay.Build()
	}
	if c.options.SessionCheckInterval != nil {
		tunnel.SessionCheckInterval = c.options.SessionCheckInterval.Build()
	}
	if c.options.IdleTimeout != nil {
		tunnel.IdleTimeout = c.options.IdleTimeout.Build()
	}
	if c.options.KeepAlive != nil {
		tunnel.KeepAlive = c.options.KeepAlive.Build()
	}
	if c.options.HandshakeTimeout != nil {
		tunnel.HandshakeTimeout = c.options.HandshakeTimeout.Build()
	}

	if err := tunnel.InitiateResolverConnection(); err != nil {
		return nil, fmt.Errorf("failed to initiate connection to resolver: %w", err)
	}

	if err := tunnel.InitiateDNSPacketConn(tServer.Addr); err != nil {
		return nil, fmt.Errorf("failed to initiate DNS packet connection: %w", err)
	}

	// c.logger.DebugContext(c.ctx, "effective MTU %d", tServer.MTU)

	if err := tunnel.InitiateKCPConn(tServer.MTU); err != nil {
		return nil, fmt.Errorf("failed to initiate KCP connection: %w", err)
	}

	// c.logger.DebugContext(c.ctx, "established KCP conn")
	if err := tunnel.InitiateNoiseChannel(); err != nil {
		// c.logger.WarnContext(c.ctx, "failed to establish Noise channel: %v", err)
		return nil, fmt.Errorf("failed to initiate noise channel: %w", err)
	}

	// c.logger.DebugContext(c.ctx, "established Noise channel")

	if err := tunnel.InitiateSmuxSession(); err != nil {
		return nil, fmt.Errorf("failed to initiate smux session: %w", err)
	}
	// c.logger.DebugContext(c.ctx, "established smux session")
	return tunnel, nil
}

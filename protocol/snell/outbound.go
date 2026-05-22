package snellprotocol

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	snell "github.com/reF1nd/sing-snell"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	obfs "github.com/sagernet/sing-box/transport/simple-obfs"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.SnellOutboundOptions](registry, C.TypeSnell, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger     log.ContextLogger
	dialer     N.Dialer
	client     *snell.Client
	pool       *snell.Pool
	serverAddr M.Socksaddr
	obfsMode   string
	obfsHost   string
	serverPort string
	psk        []byte
	version    int
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SnellOutboundOptions) (adapter.Outbound, error) {
	if options.PSK == "" {
		return nil, E.New("snell: psk is required")
	}

	switch options.ObfsMode {
	case "", "http":
	case "tls":
		ver := options.Version
		if ver == 0 {
			ver = snell.DefaultVersion
		}
		if ver >= snell.Version4 {
			return nil, E.New("snell: obfs_mode TLS is insecure and not supported for v4/v5; use ShadowTLS instead")
		}
	default:
		return nil, E.New("snell: unsupported obfs mode: ", options.ObfsMode)
	}

	serverAddr := options.ServerOptions.Build()

	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}

	version := options.Version
	if version == 0 {
		version = snell.DefaultVersion
	}

	// Build network list. If the user specified an explicit `network` field use
	// that; otherwise apply the protocol default: v3/v4/v5 enable TCP+UDP by
	// default, while v1/v2 default to TCP-only (no UDP support).
	var networks []string
	if string(options.Network) != "" {
		networks = options.Network.Build()
		for _, net := range networks {
			if net == N.NetworkUDP && version < snell.Version3 {
				return nil, E.New("snell: UDP requires version 3 or above")
			}
		}
	} else if version >= snell.Version3 {
		networks = []string{N.NetworkTCP, N.NetworkUDP}
	} else {
		networks = []string{N.NetworkTCP}
	}

	client, err := snell.NewClient([]byte(options.PSK), version)
	if err != nil {
		return nil, err
	}

	o := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeSnell, tag, networks, options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		client:     client,
		serverAddr: serverAddr,
		obfsMode:   options.ObfsMode,
		obfsHost:   options.ObfsHost,
		serverPort: fmt.Sprintf("%d", serverAddr.Port),
		psk:        []byte(options.PSK),
		version:    version,
	}

	// Connection reuse (v4+): build a pool whose factory dials + encrypts a
	// fresh stream.  The pool is only active when reuse is explicitly enabled.
	if options.Reuse && version >= snell.Version4 {
		o.pool = snell.NewPool(func(ctx context.Context) (net.Conn, error) {
			rawConn, err := outboundDialer.DialContext(ctx, N.NetworkTCP, serverAddr)
			if err != nil {
				return nil, err
			}
			return client.WrapStream(o.applyObfs(rawConn)), nil
		})
	}

	return o, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination

	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		if h.pool != nil {
			return h.client.DialContextWithPool(ctx, h.pool, destination)
		}
		rawConn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
		if err != nil {
			return nil, err
		}
		conn := h.applyObfs(rawConn)
		return h.client.DialContext(ctx, conn, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound UDP connection to ", destination)
		if h.version >= snell.Version5 {
			pc := newV5LazyPacketConn(ctx, h, destination, metadata.Protocol == C.ProtocolQUIC)
			return &packetConnWrapper{PacketConn: pc, destination: destination}, nil
		}
		rawConn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
		if err != nil {
			return nil, err
		}
		conn := h.applyObfs(rawConn)
		udpStream, err := h.client.DialUDP(ctx, conn)
		if err != nil {
			return nil, err
		}
		pc := snell.NewClientPacketConn(udpStream)
		return &packetConnWrapper{PacketConn: pc, destination: destination}, nil
	}
	return nil, os.ErrInvalid
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination

	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)

	if h.version >= snell.Version5 {
		return newV5LazyPacketConn(ctx, h, destination, metadata.Protocol == C.ProtocolQUIC), nil
	}

	rawConn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	if err != nil {
		return nil, err
	}
	conn := h.applyObfs(rawConn)
	udpStream, err := h.client.DialUDP(ctx, conn)
	if err != nil {
		return nil, err
	}
	return snell.NewClientPacketConn(udpStream), nil
}

// dialUDPOverTCP creates a UDP-over-TCP tunnel (v3/v4/v5 fallback for non-QUIC UDP).
func (h *Outbound) dialUDPOverTCP(ctx context.Context) (net.PacketConn, error) {
	rawConn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	if err != nil {
		return nil, err
	}
	conn := h.applyObfs(rawConn)
	udpStream, err := h.client.DialUDP(ctx, conn)
	if err != nil {
		return nil, err
	}
	return snell.NewClientPacketConn(udpStream), nil
}

// dialQUICProxy creates a QUIC proxy PacketConn (v5 only).
// initPayload is the first QUIC Initial packet; it is sent as part of the init frame.
func (h *Outbound) dialQUICProxy(ctx context.Context, destination M.Socksaddr, initPayload []byte) (net.PacketConn, error) {
	rawConn, err := h.dialer.DialContext(ctx, N.NetworkUDP, h.serverAddr)
	if err != nil {
		return nil, err
	}
	return snell.NewQUICProxyPacketConn(rawConn, h.psk, destination, initPayload)
}

// v5LazyPacketConn defers connection establishment to the first WriteTo call,
// allowing mode selection between QUIC proxy and UDP-over-TCP.
//
// Mode selection priority:
//  1. sniffQUIC == true  (router sniff identified QUIC before reaching this outbound)
//  2. first payload byte >= 0xc0  (QUIC long-header, e.g. Initial / Handshake / 0-RTT)
//
// Using sniff as primary handles the 0-RTT resumption case where the first packet
// is a short-header (0x40-0x7f) and would otherwise be misclassified.
type v5LazyPacketConn struct {
	outbound    *Outbound
	ctx         context.Context
	destination M.Socksaddr
	// sniffQUIC is set when the router's sniff result identified this flow as QUIC.
	// It takes priority over the first-byte heuristic.
	sniffQUIC bool

	once           sync.Once
	initCh         chan struct{} // closed once conn is ready
	conn           net.PacketConn
	connErr        error
	firstWriteQUIC bool // true when dialQUICProxy consumed initPayload
}

func newV5LazyPacketConn(ctx context.Context, ob *Outbound, dst M.Socksaddr, sniffQUIC bool) *v5LazyPacketConn {
	return &v5LazyPacketConn{
		outbound:    ob,
		ctx:         ctx,
		destination: dst,
		sniffQUIC:   sniffQUIC,
		initCh:      make(chan struct{}),
	}
}

func (c *v5LazyPacketConn) initConn(p []byte, addr net.Addr) {
	useQUIC := c.sniffQUIC || (len(p) > 0 && snell.IsQUICInitial(p[0]))
	if useQUIC {
		// Always use c.destination (resolved at ListenPacket/DialContext time, after
		// FakeIP reverse-lookup and routing) as the QUIC proxy target.
		// Do NOT use addr here, which carries the fake IP in TUN+FakeIP scenarios.
		conn, err := c.outbound.dialQUICProxy(c.ctx, c.destination, p)
		c.conn = conn
		c.connErr = err
		c.firstWriteQUIC = (err == nil)
	} else {
		conn, err := c.outbound.dialUDPOverTCP(c.ctx)
		c.conn = conn
		c.connErr = err
	}
	close(c.initCh)
}

func (c *v5LazyPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	var firstWriteQUIC bool
	c.once.Do(func() {
		c.initConn(p, addr)
		firstWriteQUIC = c.firstWriteQUIC
	})
	<-c.initCh
	if c.connErr != nil {
		return 0, c.connErr
	}
	// For QUIC proxy first write, the payload was already sent inside dialQUICProxy.
	if firstWriteQUIC {
		return len(p), nil
	}
	return c.conn.WriteTo(p, addr)
}

func (c *v5LazyPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	<-c.initCh
	if c.connErr != nil {
		return 0, nil, c.connErr
	}
	return c.conn.ReadFrom(p)
}

func (c *v5LazyPacketConn) Close() error {
	select {
	case <-c.initCh:
		if c.conn != nil {
			return c.conn.Close()
		}
		return nil
	default:
		// conn not yet initialized; nothing to close
		return nil
	}
}

func (c *v5LazyPacketConn) LocalAddr() net.Addr {
	select {
	case <-c.initCh:
		if c.conn != nil {
			return c.conn.LocalAddr()
		}
	default:
	}
	return &net.UDPAddr{}
}

func (c *v5LazyPacketConn) SetDeadline(t time.Time) error {
	select {
	case <-c.initCh:
		if c.conn != nil {
			return c.conn.SetDeadline(t)
		}
	default:
	}
	return nil
}

func (c *v5LazyPacketConn) SetReadDeadline(t time.Time) error {
	select {
	case <-c.initCh:
		if c.conn != nil {
			return c.conn.SetReadDeadline(t)
		}
	default:
	}
	return nil
}

func (c *v5LazyPacketConn) SetWriteDeadline(t time.Time) error {
	select {
	case <-c.initCh:
		if c.conn != nil {
			return c.conn.SetWriteDeadline(t)
		}
	default:
	}
	return nil
}

func (h *Outbound) applyObfs(conn net.Conn) net.Conn {
	obfsHost := h.obfsHost
	if obfsHost == "" {
		obfsHost = "bing.com"
	}
	switch h.obfsMode {
	case "http":
		return obfs.NewHTTPObfs(conn, obfsHost, h.serverPort)
	case "tls":
		return obfs.NewTLSObfs(conn, obfsHost)
	}
	return conn
}

// packetConnWrapper wraps net.PacketConn as net.Conn so it can be used in DialContext for UDP networks.
type packetConnWrapper struct {
	net.PacketConn
	destination M.Socksaddr
}

func (w *packetConnWrapper) Read(p []byte) (int, error) {
	n, _, err := w.PacketConn.ReadFrom(p)
	return n, err
}

func (w *packetConnWrapper) Write(p []byte) (int, error) {
	return w.PacketConn.WriteTo(p, w.destination)
}

func (w *packetConnWrapper) RemoteAddr() net.Addr {
	return w.destination
}

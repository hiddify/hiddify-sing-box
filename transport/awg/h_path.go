package awg

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/hiddify/mtusearch"
	"github.com/sagernet/sing-box/hiddify/peerfallback"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

// The path of the tunnel, as in the WireGuard transport (transport/wireguard/h_mtu_discovery.go and
// h_peer_fallback.go):
//   - MTU discovery: when the device starts, and whenever its connection is made again, ICMP echo
//     requests of every size up to the MTU go through the tunnel to 1.1.1.1 (2606:4700:4700::1111
//     without an IPv4 address), and the stack's MTU becomes the largest size answered (package
//     mtusearch). The requests go through the stack's own ping sockets, so the stack first goes
//     back to the configured MTU: it would split a larger request into fragments that get through.
//     When the MTU ends lower, the TCP connections made through the device are closed, so apps
//     reconnect with packets that fit. It needs the user-space stack, not useIntegratedTun.
//   - Fallback addresses: the only peer's other addresses, tried in turn when the one in use does
//     not answer (package peerfallback). A move sets the peer's endpoint, makes the bind connect
//     again, to the new address, and starts a handshake there at once.
//
// Each time the bind connects again after the first, the path may have changed: the fallback
// starts again from the peer's own address, and discovery runs again.

var (
	mtuProbeTargetIPv4 = netip.MustParseAddr("1.1.1.1")
	mtuProbeTargetIPv6 = netip.MustParseAddr("2606:4700:4700::1111")
)

type devicePath struct {
	ctx       context.Context
	logger    logger.ContextLogger
	opts      DeviceOpts
	stack     *netstack.Net // nil: no discovery
	tcp       *interrupt.Group
	fallback  *peerfallback.Fallback
	device    *Device
	publicKey device.NoisePublicKey // of the only peer

	access   sync.Mutex
	cancel   context.CancelFunc
	running  bool
	again    bool
	sequence atomic.Uint32
}

func newDevicePath(ctx context.Context, logger logger.ContextLogger, tun tunAdapter, opts DeviceOpts) *devicePath {
	p := &devicePath{ctx: ctx, logger: logger, opts: opts, tcp: interrupt.NewGroup()}
	if networkTun, isNetwork := tun.(*networkTun); isNetwork && opts.MTUDiscovery {
		p.stack = networkTun.conn
	}
	return p
}

// start begins the fallback and the first discovery, once the device is up.
func (p *devicePath) start(d *Device) {
	p.device = d
	p.publicKey, _ = peerPublicKey(d.ipcConfig)
	if bind, isBind := d.bind.(*bind_adapter); isBind {
		bind.mutex.Lock()
		bind.onReopen = p.pathChanged
		peer := bind.peer
		bind.mutex.Unlock()
		if p.publicKey != (device.NoisePublicKey{}) && peer.IsValid() && len(p.opts.Fallback) > 0 {
			publicKey := p.publicKey
			p.fallback = peerfallback.New(peerfallback.Options{
				Logger:    p.logger,
				Addresses: append([]netip.AddrPort{peer}, p.opts.Fallback...),
				Status:    p.status,
				Move: func(address netip.AddrPort) bool {
					bind.setPeer(address)
					if err := d.awgDevice.IpcSet("public_key=" + hex.EncodeToString(publicKey[:]) + "\nupdate_only=true\nendpoint=" + address.String()); err != nil {
						p.logger.Error("set the peer's address: ", err)
					}
					if err := d.awgDevice.BindUpdate(); err != nil {
						p.logger.Error("connect to ", address, ": ", err)
					}
					p.startHandshake(true) // at once, not at the next retry in 5 seconds
					return true
				},
			})
			p.fallback.Start(p.ctx)
		}
	}
	if p.stack != nil {
		p.access.Lock()
		p.startLocked(false)
		p.access.Unlock()
	}
}

func (p *devicePath) close() {
	p.fallback.Close()
	p.access.Lock()
	defer p.access.Unlock()
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
	p.running, p.again = false, false
}

// track keeps a TCP connection made through the device, to close it when the MTU is lowered.
func (p *devicePath) track(network string, conn net.Conn, err error) (net.Conn, error) {
	if p == nil || p.stack == nil || err != nil || N.NetworkName(network) != N.NetworkTCP {
		return conn, err
	}
	return p.tcp.NewConn(conn, true), nil
}

// pathChanged is called each time the bind connects again after the first.
func (p *devicePath) pathChanged() {
	if p.fallback.PathChanged() {
		return // the bind connects to the first address, which calls pathChanged again
	}
	if p.stack == nil {
		return
	}
	p.access.Lock()
	defer p.access.Unlock()
	if p.running {
		p.again = true
		return
	}
	p.startLocked(true)
}

func (p *devicePath) startLocked(handshake bool) {
	if p.cancel != nil {
		p.cancel()
	}
	ctx, cancel := context.WithCancel(p.ctx)
	p.cancel, p.running, p.again = cancel, true, false
	go func() {
		p.discover(ctx, handshake)
		p.access.Lock()
		defer p.access.Unlock()
		p.running = false
		if p.again && ctx.Err() == nil {
			p.startLocked(true)
		}
	}()
}

func (p *devicePath) discover(ctx context.Context, handshake bool) {
	configured := int(p.opts.MTU)
	target, smallest, header := mtuProbeTargetIPv4, mtusearch.MinIPv4, 20
	hasIPv4 := false
	for _, prefix := range p.opts.Address {
		hasIPv4 = hasIPv4 || prefix.Addr().Is4()
	}
	if !hasIPv4 {
		target, smallest, header = mtuProbeTargetIPv6, mtusearch.MinIPv6, 40
	}
	p.stack.UpdateMTU(configured) // larger requests would go out as fragments
	working := mtusearch.Search(ctx, smallest, configured, func(first bool) {
		if handshake {
			p.startHandshake(first)
		}
	}, func(ctx context.Context, sizes []int, timeout time.Duration) int {
		return p.round(ctx, target, header, sizes, timeout)
	})
	if ctx.Err() != nil {
		return
	}
	if working == 0 {
		p.logger.Debug("MTU discovery: no answer from ", target, " through the tunnel; the MTU stays ", configured)
		return
	}
	p.stack.UpdateMTU(working)
	if working < configured {
		p.tcp.Interrupt(true)
		p.logger.Info("MTU discovery: packets larger than ", working, " do not get through the tunnel; the MTU is ", working, " instead of ", configured)
	} else {
		p.logger.Debug("MTU discovery: the configured MTU ", configured, " gets through")
	}
}

// round sends an echo request of each size at once through the stack, and returns the largest
// size answered within timeout (0 for none).
func (p *devicePath) round(ctx context.Context, target netip.Addr, header int, sizes []int, timeout time.Duration) int {
	conn, err := p.stack.DialPingAddr(netip.Addr{}, target)
	if err != nil {
		return 0
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()
	conn.SetDeadline(time.Now().Add(timeout))
	bySequence := make(map[uint16]int, len(sizes))
	for _, size := range sizes {
		sequence := uint16(p.sequence.Add(1))
		bySequence[sequence] = size
		request := make([]byte, size-header) // the ICMP message: the stack adds the IP header
		request[0] = 8                       // echo request
		if header == 40 {
			request[0] = 128
		}
		binary.BigEndian.PutUint16(request[6:], sequence)
		if _, err := conn.Write(request); err != nil {
			return 0
		}
	}
	best, largest := 0, sizes[len(sizes)-1]
	reply := make([]byte, largest)
	for best < largest {
		n, _, err := conn.ReadFrom(reply)
		if err != nil {
			break
		}
		if n >= 8 {
			best = max(best, bySequence[binary.BigEndian.Uint16(reply[6:])])
		}
	}
	return best
}

// startHandshake starts a handshake with the peer; first drops the session keys, so it goes at
// once (WireGuard otherwise sends at most one in 5 seconds) and the server learns the new path.
func (p *devicePath) startHandshake(first bool) {
	if p.publicKey == (device.NoisePublicKey{}) || p.device.awgDevice == nil {
		return
	}
	if peer := p.device.awgDevice.LookupPeer(p.publicKey); peer != nil {
		if first {
			peer.ExpireCurrentKeypairs()
		}
		peer.SendHandshakeInitiation(false)
	}
}

func (p *devicePath) status() (time.Time, uint64) {
	state, err := p.device.IpcGet()
	if err != nil {
		return time.Time{}, 0
	}
	return peerfallback.ParseStatus(state)
}

// peerPublicKey is the public key of the only peer in a UAPI configuration.
func peerPublicKey(ipcConfig string) (device.NoisePublicKey, bool) {
	var (
		key   device.NoisePublicKey
		count int
	)
	for _, line := range strings.Split(ipcConfig, "\n") {
		if value, found := strings.CutPrefix(line, "public_key="); found {
			count++
			if decoded, err := hex.DecodeString(value); err == nil && len(decoded) == len(key) {
				copy(key[:], decoded)
			} else if decoded, err := base64.StdEncoding.DecodeString(value); err == nil && len(decoded) == len(key) {
				copy(key[:], decoded)
			}
		}
	}
	return key, count == 1 && key != device.NoisePublicKey{}
}

// setPeer makes the bind connect to address the next time it opens.
func (b *bind_adapter) setPeer(address netip.AddrPort) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.peer = address
}

// noteOpen counts the bind's opens; each after the first reports a possible path change.
func (b *bind_adapter) noteOpen() {
	b.opens++
	if b.opens > 1 && b.onReopen != nil {
		go b.onReopen()
	}
}

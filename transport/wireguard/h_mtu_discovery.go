package wireguard

import (
	"context"
	"encoding/binary"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/hiddify/mtusearch"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	N "github.com/sagernet/sing/common/network"
)

// MTU discovery. An endpoint's MTU works only when every layer under it carries the tunnel's UDP
// packets: the network, and the detour when there is one (another tunnel, as in WARP in WARP, or a
// proxy). A packet too large for one of them is lost without a word, and connections stall on
// their first full-size packet. So when the endpoint starts, and whenever its path may have changed
// (the network changed, or its connection through the detour was made again because the detour's
// selection changed or the connection was recovered), it sends ICMP echo requests of every size
// from the smallest MTU to the configured one through the tunnel to 1.1.1.1 (2606:4700:4700::1111
// without an IPv4 address), as package mtusearch says. Each request goes out as one tunnel UDP
// packet of that size plus the WireGuard headers. The stack's MTU becomes the largest size
// answered, within about a second. When nothing is answered (a server that drops ICMP, or no route
// to the target), the MTU stays as configured.
//
// A WARP server keeps sending to the old path until the next handshake, which WireGuard starts only
// after hearing nothing for 15 seconds. So when the path changes, the endpoint drops its session
// keys and starts a handshake at once, as WireGuard does when a peer's endpoint changes. A TCP
// connection that began before the MTU was lowered keeps the larger segment size it agreed on: its
// own larger packets are answered with "packet too big", as a router on the path does, but the
// server's are lost in the tunnel, and nothing tells the server. So when the MTU is lowered, the
// TCP connections made through the endpoint before are closed, and apps reconnect.

var (
	mtuProbeTargetIPv4 = netip.MustParseAddr("1.1.1.1")
	mtuProbeTargetIPv6 = netip.MustParseAddr("2606:4700:4700::1111")
)

type mtuProber struct {
	endpoint   *Endpoint
	id         uint16
	sequence   atomic.Uint32
	access     sync.Mutex
	pending    map[uint16]func() // sequence → called when its reply arrives
	cancel     context.CancelFunc
	running    bool
	again      bool // the path changed during a run
	handshake  bool // the next run starts a handshake first
	discovered atomic.Uint32
	tcp        *interrupt.Group // the TCP connections made through the endpoint
}

// setupMTUDiscovery makes the prober, unless discovery is off or not possible: it needs the
// user-space stack, whose MTU it changes.
func (e *Endpoint) setupMTUDiscovery() {
	if _, isStack := e.tunDevice.(*stackDevice); !isStack || e.options.DisableMTUDiscovery || e.mtuProbe != nil {
		return
	}
	e.mtuProbe = &mtuProber{endpoint: e, id: uint16(rand.Uint32()), pending: make(map[uint16]func()), tcp: interrupt.NewGroup()}
	e.returnDevice.prober = e.mtuProbe
}

// discoveredMTU is the MTU found by discovery, or the configured one.
func (e *Endpoint) discoveredMTU() uint32 {
	if e.mtuProbe != nil {
		if mtu := e.mtuProbe.discovered.Load(); mtu != 0 {
			return mtu
		}
	}
	return e.options.MTU
}

// track keeps a TCP connection made through the endpoint, to close it when the MTU is lowered.
func (p *mtuProber) track(network string, conn net.Conn, err error) (net.Conn, error) {
	if p == nil || err != nil || N.NetworkName(network) != N.NetworkTCP {
		return conn, err
	}
	return p.tcp.NewConn(conn, true), nil
}

// filter takes the probe replies out of the packets the device received.
func (p *mtuProber) filter(bufs [][]byte, offset int) [][]byte {
	if p == nil {
		return bufs
	}
	for i, packet := range bufs {
		if p.take(packet[offset:]) {
			kept := make([][]byte, 0, len(bufs)-1)
			kept = append(kept, bufs[:i]...)
			for _, packet := range bufs[i+1:] {
				if !p.take(packet[offset:]) {
					kept = append(kept, packet)
				}
			}
			return kept
		}
	}
	return bufs
}

// take reports an echo reply to a probe, and tells its sender.
func (p *mtuProber) take(packet []byte) bool {
	var icmp []byte
	switch {
	case len(packet) >= 28 && packet[0]>>4 == 4 && packet[9] == 1: // ICMP
		icmp = packet[int(packet[0]&0xf)*4:]
		if len(icmp) < 8 || icmp[0] != 0 { // echo reply
			return false
		}
	case len(packet) >= 48 && packet[0]>>4 == 6 && packet[6] == 58: // ICMPv6
		icmp = packet[40:]
		if icmp[0] != 129 { // echo reply
			return false
		}
	default:
		return false
	}
	if binary.BigEndian.Uint16(icmp[4:]) != p.id {
		return false
	}
	sequence := binary.BigEndian.Uint16(icmp[6:])
	p.access.Lock()
	answered := p.pending[sequence]
	delete(p.pending, sequence)
	p.access.Unlock()
	if answered != nil {
		answered()
	}
	return true
}

// start runs discovery, stopping a run in progress.
func (p *mtuProber) start() {
	if p == nil {
		return
	}
	p.access.Lock()
	defer p.access.Unlock()
	p.startLocked(false)
}

func (p *mtuProber) startLocked(handshake bool) {
	if p.cancel != nil {
		p.cancel()
	}
	ctx, cancel := context.WithCancel(p.endpoint.options.Context)
	p.cancel, p.running, p.again = cancel, true, false
	go p.run(ctx, handshake)
}

// pathChanged starts a handshake and runs discovery again: at once, or after the run in progress.
func (p *mtuProber) pathChanged() {
	if p == nil {
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

func (p *mtuProber) stop() {
	if p == nil {
		return
	}
	p.access.Lock()
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
	p.running, p.again = false, false
	p.access.Unlock()
}

func (p *mtuProber) run(ctx context.Context, handshake bool) {
	p.discover(ctx, handshake)
	p.access.Lock()
	defer p.access.Unlock()
	p.running = false
	if p.again && ctx.Err() == nil {
		p.startLocked(true)
	}
}

// startHandshake starts a handshake with each peer; with renew it first drops the session keys,
// so the handshake goes at once (WireGuard otherwise sends at most one in 5 seconds).
func (p *mtuProber) startHandshake(renew bool) {
	wgDevice := p.endpoint.device.Load()
	if wgDevice == nil {
		return
	}
	for _, peer := range p.endpoint.peers {
		if wgPeer, loaded := wgDevice.LookupActivePeer(peer.publicKey); loaded {
			if renew {
				wgPeer.ExpireCurrentKeypairs()
			}
			wgPeer.SendHandshakeInitiation(false)
		}
	}
}

func (p *mtuProber) discover(ctx context.Context, handshake bool) {
	e := p.endpoint
	stack := e.tunDevice.(*stackDevice)
	configured := int(e.options.MTU)
	source, target, smallest := stack.Inet4Address(), mtuProbeTargetIPv4, mtusearch.MinIPv4
	if !source.IsValid() {
		source, target, smallest = stack.Inet6Address(), mtuProbeTargetIPv6, mtusearch.MinIPv6
	}
	if !source.IsValid() {
		return
	}
	working := mtusearch.Search(ctx, smallest, configured, func(first bool) {
		if handshake {
			p.startHandshake(first)
		}
	}, func(ctx context.Context, sizes []int, timeout time.Duration) int {
		return p.round(ctx, source, target, sizes, timeout)
	})
	if ctx.Err() != nil {
		return
	}
	if working == 0 {
		e.options.Logger.Debug("MTU discovery: no answer from ", target, " through the tunnel; the MTU stays ", configured)
		return
	}
	lowered := working < stack.router.memoryTun.MTU()
	stack.router.memoryTun.UpdateMTU(working)
	if lowered {
		p.tcp.Interrupt(true)
	}
	if previous := p.discovered.Swap(uint32(working)); previous == uint32(working) {
		return
	}
	if working < configured {
		e.options.Logger.Info("MTU discovery: packets larger than ", working, " do not get through the tunnel; the MTU is ", working, " instead of ", configured)
	} else {
		e.options.Logger.Debug("MTU discovery: the configured MTU ", configured, " gets through")
	}
}

// round sends an echo request of each size at once, and returns the largest size answered within
// timeout (0 for none). It returns early once the largest one is answered.
func (p *mtuProber) round(ctx context.Context, source, target netip.Addr, sizes []int, timeout time.Duration) int {
	wgDevice := p.endpoint.device.Load()
	if wgDevice == nil || len(sizes) == 0 {
		return 0
	}
	var (
		best     atomic.Int32
		largest  = sizes[len(sizes)-1]
		done     = make(chan struct{})
		doneOnce sync.Once
	)
	packets := make([][]byte, 0, len(sizes))
	sequences := make([]uint16, 0, len(sizes))
	p.access.Lock()
	for _, size := range sizes {
		sequence := uint16(p.sequence.Add(1))
		sequences = append(sequences, sequence)
		packets = append(packets, buildEchoRequest(source, target, p.id, sequence, size))
		p.pending[sequence] = func() {
			for {
				current := best.Load()
				if int32(size) <= current || best.CompareAndSwap(current, int32(size)) {
					break
				}
			}
			if size == largest {
				doneOnce.Do(func() { close(done) })
			}
		}
	}
	p.access.Unlock()
	defer func() {
		p.access.Lock()
		for _, sequence := range sequences {
			delete(p.pending, sequence)
		}
		p.access.Unlock()
	}()
	peer := wgDevice.AllowedIPs().LookupFromPacket(source, target, packets[0])
	if peer == nil {
		return 0
	}
	p.endpoint.resume()
	peer.WritePackets(packets)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	case <-ctx.Done():
	}
	return int(best.Load())
}

// buildEchoRequest is an ICMP (ICMPv6) echo request of size bytes in all, with "don't fragment".
func buildEchoRequest(source, target netip.Addr, id, sequence uint16, size int) []byte {
	packet := make([]byte, size)
	var icmp []byte
	if source.Is4() {
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:], uint16(size))
		binary.BigEndian.PutUint16(packet[4:], uint16(rand.Uint32()))
		binary.BigEndian.PutUint16(packet[6:], 0x4000) // don't fragment
		packet[8] = 64
		packet[9] = 1
		copy(packet[12:16], source.AsSlice())
		copy(packet[16:20], target.AsSlice())
		binary.BigEndian.PutUint16(packet[10:], ^checksum(packet[:20], 0))
		icmp = packet[20:]
		icmp[0] = 8
	} else {
		packet[0] = 0x60
		binary.BigEndian.PutUint16(packet[4:], uint16(size-40))
		packet[6] = 58
		packet[7] = 64
		copy(packet[8:24], source.AsSlice())
		copy(packet[24:40], target.AsSlice())
		icmp = packet[40:]
		icmp[0] = 128
	}
	binary.BigEndian.PutUint16(icmp[4:], id)
	binary.BigEndian.PutUint16(icmp[6:], sequence)
	var initial uint32
	if !source.Is4() { // the IPv6 pseudo-header
		initial = uint32(checksum(packet[8:40], uint32(len(icmp))+58))
	}
	binary.BigEndian.PutUint16(icmp[2:], ^checksum(icmp, initial))
	return packet
}

// checksum is the folded one's complement sum of data, added to sum.
func checksum(data []byte, sum uint32) uint16 {
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return uint16(sum)
}

// answerTooBig answers a packet larger than the MTU with "packet too big", as a router on the path
// does, and reports that it did. Only a connection that began before discovery lowered the MTU
// sends such packets; the stack then sends smaller ones on it.
func (r *peerRouter) answerTooBig(packet []byte) bool {
	mtu := r.memoryTun.MTU()
	if len(packet) <= mtu {
		return false
	}
	source := r.inet4Address
	if header.IPVersion(packet) == header.IPv6Version {
		source = r.inet6Address
	}
	if reply, built := tun.BuildICMPError(packet, tun.ICMPErrorPacketTooBig, source, uint32(mtu), 0); built {
		r.memoryTun.WritePackets([][]byte{reply})
	}
	return true
}

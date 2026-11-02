package route

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// A TCP connection from an app to an IPv6 address goes through the TUN's own handshake at once,
// before the proxy has tried the destination. When the proxy's exit has no IPv6, the proxy then
// closes the stream, and the app sees a connection that opened and died: Chrome shows
// ERR_CONNECTION_CLOSED and never tries the IPv4 address (hiddify-app #2307, #2420). A reset at
// that point is no better, since an app falls back only when the connect itself fails.
//
// So the router carries such a connection itself (route option ipv6_fallback): it dials the
// IPv6 address as asked, lets the app's first bytes go, and watches for the destination's first
// byte. If the proxy gives nothing, the same proxy is dialed again with the domain the app named
// (sniffed from its client hello or request, the proxy resolving it as it can), the bytes the app
// sent are replayed, and the connection goes on. The app never sees the failure. Each outcome
// teaches the outbound's IPv6 (adapter.IPv6Capability): once an outbound is known to have no
// IPv6, the DNS rule ipv6_by_outbound hands the apps no AAAA answers for it and the route rule
// ipv6_unavailable_via refuses its IPv6 connections before the handshake, so the apps go IPv4
// on their own; an outbound found carrying IPv6 is left alone.

// hIPv6FirstByteTimeout bounds the wait for the destination's first byte over IPv6. An exit
// with no IPv6 route fails at once and the proxy closes the stream; an exit whose IPv6 route
// leads nowhere lets the connection hang until its kernel gives up, and the app with it, so a
// destination silent for this long is carried over IPv4 as well.
const hIPv6FirstByteTimeout = 10 * time.Second

// hIPv6ReplayLimit bounds what the app may send before the destination's first byte and still
// be replayed over IPv4: a TLS client hello, an HTTP request, many times over. Past it the
// connection goes on as it is.
const hIPv6ReplayLimit = 64 * 1024

// hIPv6FallbackApplies says whether a TCP connection goes through hNewIPv6Connection: one to an
// IPv6 address the app chose (a domain is the outbound's to resolve, and a resolved address list
// has its own fallback), with nothing else rewriting its stream.
func hIPv6FallbackApplies(metadata *adapter.InboundContext) bool {
	return metadata.Network == N.NetworkTCP &&
		metadata.Destination.IsIPv6() &&
		len(metadata.DestinationAddresses) == 0 &&
		!metadata.TLSFragment && !metadata.TLSRecordFragment && metadata.TLSSpoof == ""
}

// hSetIPv6Fallback turns the carry-over on in the connection manager, where every connection
// to an outbound arrives: from the router, and from the groups that route connections themselves.
func hSetIPv6Fallback(connection adapter.ConnectionManager, enabled bool) {
	if manager, isManager := connection.(*ConnectionManager); isManager {
		manager.hIPv6Fallback = enabled
	}
}

// hNewIPv6Connection is NewConnection for a connection to an IPv6 address, with the carry-over
// described above. capability, when there is one, learns from the outcome.
func (m *ConnectionManager) hNewIPv6Connection(ctx context.Context, dialer N.Dialer, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc, capability adapter.IPv6Capability) {
	ctx = adapter.WithContext(ctx, &metadata)
	destination := metadata.Destination
	var fallback M.Socksaddr
	if metadata.Domain != "" {
		fallback = M.Socksaddr{Fqdn: metadata.Domain, Port: destination.Port}
	}
	observe := func(carried bool) {
		if capability == nil {
			return
		}
		tag := metadata.GetRealOutbound()
		if tag == "" {
			tag = metadata.RouteOutbound
		}
		if tag != "" {
			capability.ObserveIPv6(tag, carried)
		}
	}
	// An outbound known not to carry IPv6 (verified at its URL test, declared by its link, or
	// taught by earlier connections) is not asked again: the connection goes straight over the
	// domain. One known to carry it is watched like the rest, which costs no traffic, so an exit
	// that loses IPv6 is noticed from its connections and they are carried over anyway.
	if capability != nil && metadata.RouteOutbound != "" {
		if supported, known := capability.OutboundIPv6(metadata.RouteOutbound); known && !supported && fallback.IsValid() {
			m.logger.DebugContext(ctx, "IPv6 destination ", destination, " through an outbound without IPv6, carried over ", fallback)
			remote, err := dialer.DialContext(ctx, N.NetworkTCP, fallback)
			if err != nil {
				m.hFailBeforeCopy(ctx, conn, nil, onClose, E.Cause(err, "open connection to ", fallback, hDialerString(dialer, &metadata)))
				return
			}
			m.hCopyBothWays(ctx, conn, remote, onClose)
			return
		}
	}
	remote, err := dialer.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		// the outbound itself could not open it: a proxy that reports its connects (SOCKS, HTTP,
		// Hysteria2, WireGuard) said so, or direct has no route
		if !fallback.IsValid() {
			m.hFailBeforeCopy(ctx, conn, nil, onClose, E.Cause(err, "open connection to ", destination, hDialerString(dialer, &metadata)))
			return
		}
		m.logger.InfoContext(ctx, "IPv6 destination ", destination, " could not be opened (", err, "), carrying it over ", fallback)
		remote, err = dialer.DialContext(ctx, N.NetworkTCP, fallback)
		if err != nil {
			m.hFailBeforeCopy(ctx, conn, nil, onClose, E.Cause(err, "open connection to ", fallback, hDialerString(dialer, &metadata)))
			return
		}
		observe(false)
		m.hCopyBothWays(ctx, conn, remote, onClose)
		return
	}
	if !fallback.IsValid() {
		// nothing to carry it over with: the connection goes on as it would have
		m.hCopyBothWays(ctx, conn, remote, onClose)
		return
	}
	if err = N.ReportConnHandshakeSuccess(conn, remote); err != nil {
		m.hFailBeforeCopy(ctx, conn, remote, onClose, E.Cause(err, "report handshake success"))
		return
	}
	swapper := newHIPv6Swapper(remote, hIPv6ReplayLimit)
	// the request header goes now, on its own, so the exit tries the destination even for an
	// app that waits for the server to speak first; the app's bytes follow through the copy
	if N.NeedHandshakeForWrite(remote) {
		if _, err = swapper.Write(nil); err != nil {
			m.hFailBeforeCopy(ctx, conn, remote, onClose, E.Cause(err, "write request to ", destination))
			return
		}
	}
	var done atomic.Bool
	go m.connectionCopy(ctx, conn, swapper, false, &done, onClose)

	first, readErr := swapper.readFirst(hIPv6FirstByteTimeout)
	if len(first) > 0 {
		observe(true)
		swapper.settle()
		m.hStartDownload(ctx, conn, swapper, first, &done, onClose)
		return
	}
	if swapper.overflowed() {
		// too much went out to say it again: the app gets what the proxy gave, as before
		m.hFailAfterCopy(ctx, conn, swapper, &done, onClose, E.Cause(readErr, "IPv6 destination ", destination, " gave nothing"))
		return
	}
	m.logger.InfoContext(ctx, "IPv6 destination ", destination, " gave nothing (", readErr, "), carrying it over ", fallback)
	next, err := dialer.DialContext(ctx, N.NetworkTCP, fallback)
	if err != nil {
		m.hFailAfterCopy(ctx, conn, swapper, &done, onClose, E.Cause(err, "open connection to ", fallback, hDialerString(dialer, &metadata)))
		return
	}
	if err = swapper.swap(next); err != nil {
		m.hFailAfterCopy(ctx, conn, swapper, &done, onClose, E.Cause(err, "replay to ", fallback))
		return
	}
	first, readErr = swapper.readFirst(hIPv6FirstByteTimeout)
	if len(first) > 0 {
		// IPv4 answered where IPv6 got nothing: that is the exit, not the destination
		observe(false)
		swapper.settle()
		m.hStartDownload(ctx, conn, swapper, first, &done, onClose)
		return
	}
	// the destination answers over neither family: nothing about IPv6 to learn
	m.hFailAfterCopy(ctx, conn, swapper, &done, onClose, E.Cause(readErr, "destination ", fallback, " gave nothing over IPv4 either"))
}

// hCopyBothWays is NewConnection from a dialed connection on: the standard copy in both
// directions, without the splice and the TLS tricks (hIPv6FallbackApplies left those out).
func (m *ConnectionManager) hCopyBothWays(ctx context.Context, conn net.Conn, remote net.Conn, onClose N.CloseHandlerFunc) {
	if err := N.ReportConnHandshakeSuccess(conn, remote); err != nil {
		m.hFailBeforeCopy(ctx, conn, remote, onClose, E.Cause(err, "report handshake success"))
		return
	}
	var done atomic.Bool
	if N.NeedHandshakeForWrite(remote) {
		if _, err := remote.Write(nil); err != nil {
			m.hFailBeforeCopy(ctx, conn, remote, onClose, E.Cause(err, "write request"))
			return
		}
	}
	go m.connectionCopy(ctx, conn, remote, false, &done, onClose)
	go m.connectionCopy(ctx, remote, conn, true, &done, onClose)
}

// hStartDownload starts the copy from the destination to the app, first bytes first.
func (m *ConnectionManager) hStartDownload(ctx context.Context, conn net.Conn, remote net.Conn, first []byte, done *atomic.Bool, onClose N.CloseHandlerFunc) {
	var source net.Conn = remote
	if len(first) > 0 {
		buffer := buf.NewSize(len(first))
		common.Must1(buffer.Write(first))
		source = bufio.NewCachedConn(remote, buffer)
	}
	go m.connectionCopy(ctx, source, conn, true, done, onClose)
}

// hFailBeforeCopy ends a connection that failed before any copy started: the inbound hears of
// the failed handshake, as in NewConnection.
func (m *ConnectionManager) hFailBeforeCopy(ctx context.Context, conn net.Conn, remote net.Conn, onClose N.CloseHandlerFunc, err error) {
	m.logger.ErrorContext(ctx, err)
	if remote != nil {
		remote.Close()
	}
	N.CloseOnHandshakeFailure(conn, onClose, err)
}

// hFailAfterCopy ends a connection whose upload copy is running: whichever side ends last
// reports to onClose, as connectionCopy does.
func (m *ConnectionManager) hFailAfterCopy(ctx context.Context, conn net.Conn, remote net.Conn, done *atomic.Bool, onClose N.CloseHandlerFunc, err error) {
	m.logger.ErrorContext(ctx, err)
	if done.Swap(true) && onClose != nil {
		onClose(err)
	}
	common.Close(conn, remote)
}

func hDialerString(dialer N.Dialer, metadata *adapter.InboundContext) string {
	outbound, isOutbound := dialer.(adapter.Outbound)
	if !isOutbound {
		return ""
	}
	s := " using outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
	if real := metadata.GetRealOutbound(); real != "" && real != outbound.Tag() {
		s += "[" + real + "]"
	}
	return s
}

// hIPv6Swapper is the connection to the destination as the upload copy sees it: it records what
// the app sends until the destination's first byte, so the same bytes can be said again to the
// replacement the carry-over dials, and swallows a write the dying first connection refuses,
// since the replay will carry it.
type hIPv6Swapper struct {
	mu          sync.Mutex
	target      net.Conn
	record      []byte
	recording   bool
	overflow    bool
	closedWrite bool
	targetDead  bool
	limit       int
}

func newHIPv6Swapper(target net.Conn, limit int) *hIPv6Swapper {
	return &hIPv6Swapper{target: target, recording: true, limit: limit}
}

func (s *hIPv6Swapper) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recording {
		if len(s.record)+len(b) <= s.limit {
			s.record = append(s.record, b...)
		} else {
			s.overflow = true
			s.recording = false
			s.record = nil
		}
	}
	if s.targetDead && s.recording {
		return len(b), nil // the replay carries it
	}
	n, err := s.target.Write(b)
	if err != nil && s.recording {
		s.targetDead = true
		return len(b), nil
	}
	return n, err
}

func (s *hIPv6Swapper) Read(b []byte) (int, error) {
	s.mu.Lock()
	target := s.target
	s.mu.Unlock()
	return target.Read(b)
}

// readFirst waits for the destination's first bytes, at most timeout. A read left pending after
// the timeout ends with the connection it was on, which swap closes.
func (s *hIPv6Swapper) readFirst(timeout time.Duration) ([]byte, error) {
	s.mu.Lock()
	target := s.target
	s.mu.Unlock()
	type outcome struct {
		data []byte
		err  error
	}
	results := make(chan outcome, 1)
	go func() {
		buffer := make([]byte, 16*1024)
		n, err := target.Read(buffer)
		results <- outcome{buffer[:n], err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-results:
		return result.data, result.err
	case <-timer.C:
		return nil, E.New("no answer within ", timeout)
	}
}

// swap replaces the destination connection: what the app sent so far is said again to next,
// then the upload copy goes on into it. The old connection is closed.
func (s *hIPv6Swapper) swap(next net.Conn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.target
	if len(s.record) > 0 {
		if _, err := next.Write(s.record); err != nil {
			next.Close()
			return err
		}
	} else if N.NeedHandshakeForWrite(next) {
		if _, err := next.Write(nil); err != nil {
			next.Close()
			return err
		}
	}
	if s.closedWrite {
		if closer, isCloser := next.(N.WriteCloser); isCloser {
			closer.CloseWrite()
		}
	}
	s.target = next
	s.targetDead = false
	old.Close()
	return nil
}

// settle ends the recording: the destination answered, there is nothing to say again.
func (s *hIPv6Swapper) settle() {
	s.mu.Lock()
	s.recording = false
	s.record = nil
	s.mu.Unlock()
}

func (s *hIPv6Swapper) overflowed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.overflow
}

func (s *hIPv6Swapper) CloseWrite() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closedWrite = true
	if closer, isCloser := s.target.(N.WriteCloser); isCloser {
		return closer.CloseWrite()
	}
	return s.target.Close()
}

func (s *hIPv6Swapper) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.target.Close()
}

func (s *hIPv6Swapper) LocalAddr() net.Addr  { return s.current().LocalAddr() }
func (s *hIPv6Swapper) RemoteAddr() net.Addr { return s.current().RemoteAddr() }
func (s *hIPv6Swapper) SetDeadline(t time.Time) error {
	return s.current().SetDeadline(t)
}
func (s *hIPv6Swapper) SetReadDeadline(t time.Time) error  { return s.current().SetReadDeadline(t) }
func (s *hIPv6Swapper) SetWriteDeadline(t time.Time) error { return s.current().SetWriteDeadline(t) }

func (s *hIPv6Swapper) current() net.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.target
}

var _ N.WriteCloser = (*hIPv6Swapper)(nil)

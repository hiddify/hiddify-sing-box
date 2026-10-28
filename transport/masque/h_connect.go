package masque

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/sagernet/quic-go/http3"
	E "github.com/sagernet/sing/common/exceptions"
)

// HTTP versions of the tunnel (vhttp).
const (
	ModeHTTP3 = "h3"
	ModeHTTP2 = "h2"
	// ModeAuto tries HTTP/3 and falls back to HTTP/2: from some networks Cloudflare ignores QUIC
	// without an error, so HTTP/3 only stalls. Ported from Leadaxe/sing-box-lx SPEC 074 and 121.
	ModeAuto = "auto"
)

// autoFallbackDelay is how long HTTP/3 has before HTTP/2 starts too: a working HTTP/3
// handshake takes well under a second even through proxies.
var autoFallbackDelay = 3 * time.Second

// failoverAfter consecutive failed connects to an endpoint ask for another one.
const failoverAfter = 2

// connectTunnel is ConnectTunnel; tests replace it.
var connectTunnel = ConnectTunnel

// autoMemoryWindows is how long an HTTP/2 win is remembered, one step further on each HTTP/2 win
// in a row: a passing HTTP/3 failure (Cloudflare refuses some connects right after a key is
// enrolled) must not park the tunnel on HTTP/2 for good.
var autoMemoryWindows = []time.Duration{time.Second, 10 * time.Second, 30 * time.Second, 5 * time.Minute, 10 * time.Minute}

type connection struct {
	udpConn net.PacketConn
	tr      *http3.Transport
	ipConn  *connectip.Conn
	http2   bool
}

func (c *connection) close() {
	if c.ipConn != nil {
		c.ipConn.Close()
	}
	if c.udpConn != nil {
		c.udpConn.Close()
	}
	if c.tr != nil {
		c.tr.Close()
	}
}

func (e *Tunnel) mode() string {
	switch e.options.Mode {
	case ModeHTTP2, ModeHTTP3, ModeAuto:
		return e.options.Mode
	}
	if e.options.UseHTTP2 {
		return ModeHTTP2
	}
	return ModeHTTP3
}

// connectLeg opens one tunnel over HTTP/3 or HTTP/2 to the current endpoint of that version.
func (e *Tunnel) connectLeg(ctx context.Context, http2 bool) (*connection, net.Addr, error) {
	e.endpointAccess.Lock()
	endpoint := e.options.Endpoint
	if http2 && e.options.H2Endpoint != nil {
		endpoint = e.options.H2Endpoint
	}
	e.endpointAccess.Unlock()
	connectURI := e.options.ConnectURI
	if connectURI == "" {
		connectURI = DefaultConnectURI
	}
	udpConn, tr, ipConn, rsp, err := connectTunnel(ctx, e.options.Dialer, e.options.TLSConfig,
		DefaultQuicConfig(e.options.UDPKeepalivePeriod, e.options.UDPInitialPacketSize),
		connectURI, endpoint, http2)
	conn := &connection{udpConn, tr, ipConn, http2}
	if err != nil {
		conn.close()
		return nil, endpoint, err
	}
	if rsp.StatusCode != http.StatusOK {
		conn.close()
		return nil, endpoint, E.New("tunnel connection failed: ", rsp.Status)
	}
	return conn, endpoint, nil
}

// connect opens a tunnel in the configured mode and reports the outcome of each endpoint.
func (e *Tunnel) connect() (*connection, error) {
	switch e.mode() {
	case ModeHTTP2:
		return e.connectReported(true)
	case ModeAuto:
		return e.connectAuto()
	default:
		return e.connectReported(false)
	}
}

func (e *Tunnel) connectReported(http2 bool) (*connection, error) {
	start := time.Now()
	conn, endpoint, err := e.connectLeg(e.ctx, http2)
	e.report(endpoint, http2, time.Since(start), err)
	return conn, err
}

type legResult struct {
	http2    bool
	conn     *connection
	endpoint net.Addr
	elapsed  time.Duration
	err      error
}

// connectAuto starts HTTP/3, and HTTP/2 after autoFallbackDelay or as soon as HTTP/3 fails;
// the first leg to connect wins. A late success of the other leg is closed. An HTTP/2 win is
// remembered for the next connects for a while (see autoMemoryWindows).
func (e *Tunnel) connectAuto() (*connection, error) {
	if e.rememberedHTTP2() {
		conn, err := e.connectReported(true)
		if err == nil {
			return conn, nil
		}
		e.autoAccess.Lock()
		e.http2Until = time.Time{}
		e.autoAccess.Unlock()
		e.logger.InfoContext(e.ctx, "MASQUE: remembered HTTP/2 failed, trying HTTP/3 first again: ", err)
	}
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	results := make(chan legResult, 2)
	startLeg := func(http2 bool) {
		go func() {
			start := time.Now()
			conn, endpoint, err := e.connectLeg(ctx, http2)
			results <- legResult{http2, conn, endpoint, time.Since(start), err}
		}()
	}
	startLeg(false)
	timer := time.NewTimer(autoFallbackDelay)
	defer timer.Stop()
	started, pending := 1, 1
	var errs []error
	for {
		select {
		case <-e.ctx.Done():
			go drainLegs(results, pending)
			return nil, e.ctx.Err()
		case <-timer.C:
			if started == 1 {
				e.logger.InfoContext(e.ctx, "MASQUE: no HTTP/3 connection after ", autoFallbackDelay, ", trying HTTP/2")
				startLeg(true)
				started++
				pending++
			}
		case result := <-results:
			pending--
			if result.err != nil {
				errs = append(errs, result.err)
				e.report(result.endpoint, result.http2, result.elapsed, result.err)
				if started == 1 {
					startLeg(true)
					started++
					pending++
					continue
				}
				if pending == 0 {
					return nil, E.Errors(errs...)
				}
				continue
			}
			e.report(result.endpoint, result.http2, result.elapsed, nil)
			e.rememberWinner(result.http2)
			go drainLegs(results, pending)
			return result.conn, nil
		}
	}
}

// drainLegs closes the late successes of legs that lost.
func drainLegs(results chan legResult, pending int) {
	for ; pending > 0; pending-- {
		if result := <-results; result.conn != nil {
			result.conn.close()
		}
	}
}

func (e *Tunnel) rememberedHTTP2() bool {
	e.autoAccess.Lock()
	defer e.autoAccess.Unlock()
	return time.Now().Before(e.http2Until)
}

func (e *Tunnel) rememberWinner(http2 bool) {
	e.autoAccess.Lock()
	defer e.autoAccess.Unlock()
	if !http2 {
		e.http2Step = 0
		e.http2Until = time.Time{}
		return
	}
	window := autoMemoryWindows[min(e.http2Step, len(autoMemoryWindows)-1)]
	e.http2Until = time.Now().Add(window)
	e.http2Step++
	e.logger.InfoContext(e.ctx, "MASQUE: using HTTP/2, trying HTTP/3 again after ", window)
}

// report passes the outcome of a connect to the endpoint's owner (scores), and after
// failoverAfter failures in a row asks it for another endpoint.
func (e *Tunnel) report(endpoint net.Addr, http2 bool, elapsed time.Duration, err error) {
	if endpoint == nil || errors.Is(err, context.Canceled) && e.ctx.Err() != nil {
		return
	}
	e.endpointAccess.Lock()
	onConnected, nextEndpoint := e.options.OnConnected, e.options.NextEndpoint
	if err == nil {
		e.failures[http2] = 0
		e.endpointAccess.Unlock()
		if onConnected != nil {
			onConnected(endpoint, http2, elapsed)
		}
		return
	}
	e.failures[http2]++
	failed := e.failures[http2] >= failoverAfter
	if failed {
		e.failures[http2] = 0
	}
	e.endpointAccess.Unlock()
	if !failed || nextEndpoint == nil {
		return
	}
	next := nextEndpoint(endpoint, http2)
	if next == nil {
		return
	}
	e.endpointAccess.Lock()
	// the same choice as connectLeg: HTTP/2 uses H2Endpoint when there is one
	if http2 && e.options.H2Endpoint != nil {
		e.options.H2Endpoint = next
	} else {
		e.options.Endpoint = next
	}
	e.endpointAccess.Unlock()
	e.logger.InfoContext(e.ctx, "MASQUE: switched endpoint ", endpoint, " -> ", next)
}

// ResetConnection drops the current connection, so the next use connects again (after a network
// change, the old path may be gone).
func (e *Tunnel) ResetConnection() {
	e.mtx.Lock()
	ipConn := e.ipConn
	e.mtx.Unlock()
	if ipConn != nil {
		e.closeIpConn(ipConn)
	}
}

// SetFailover sets the endpoint callbacks (see TunnelOptions) before the tunnel starts.
func (e *Tunnel) SetFailover(onConnected func(endpoint net.Addr, http2 bool, elapsed time.Duration), nextEndpoint func(failed net.Addr, http2 bool) net.Addr) {
	e.endpointAccess.Lock()
	defer e.endpointAccess.Unlock()
	e.options.OnConnected = onConnected
	e.options.NextEndpoint = nextEndpoint
}

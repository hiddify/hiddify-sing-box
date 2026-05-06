package tooska

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/sagernet/sing-box/protocol/hiddify/tooska/scanner"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

const maxDialAttempts = 5

// dialOutcome separates "proxy is broken" from "proxy is fine but the
// destination is unreachable". Only the former feeds back into scoring.
type dialOutcome int

const (
	dialOK dialOutcome = iota
	dialProxyFault
	dialDestinationFault
)

func (h *Outbound) dialThroughPool(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	working := h.pool.working(0)
	if len(working) == 0 {
		return nil, E.New("tooska: no working endpoint available yet")
	}

	attempts := maxDialAttempts
	if attempts > len(working) {
		attempts = len(working)
	}

	var lastErr error
	for i := 0; i < attempts; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		ep := working[i]
		serverAddr := M.ParseSocksaddrHostPort(ep.IP, uint16(ep.Port))
		conn, outcome, err := h.dialOne(ctx, ep.Protocol, serverAddr, destination)
		if outcome == dialOK {
			h.pool.recordHit(scanner.Result{
				IP:        ep.IP,
				Port:      ep.Port,
				Protocol:  ep.Protocol,
				LatencyMS: ep.LatencyMS,
				CheckedAt: time.Now().UTC(),
			})
			h.kickRescanOnConnect()
			return conn, nil
		}
		lastErr = err
		h.logger.DebugContext(ctx, "tooska dial via ", ep.IP, ":", ep.Port, " (", ep.Protocol, ") ", outcomeLabel(outcome), ": ", err)
		if outcome == dialProxyFault {
			h.pool.recordMiss(ep.IP, ep.Port)
		}
	}

	h.kickRescanOnConnect()
	if lastErr == nil {
		lastErr = E.New("tooska: every working endpoint refused the dial")
	}
	return nil, lastErr
}

func outcomeLabel(o dialOutcome) string {
	switch o {
	case dialProxyFault:
		return "proxy fault"
	case dialDestinationFault:
		return "destination fault"
	default:
		return "ok"
	}
}

func (h *Outbound) dialOne(ctx context.Context, proto scanner.Protocol, server, destination M.Socksaddr) (net.Conn, dialOutcome, error) {
	tcpConn, err := h.upstream.DialContext(ctx, N.NetworkTCP, server)
	if err != nil {
		return nil, dialProxyFault, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = tcpConn.SetDeadline(deadline)
	}
	switch proto {
	case scanner.ProtoSOCKS5:
		resp, err := socks.ClientHandshake5(tcpConn, socks5.CommandConnect, destination, "", "")
		if err != nil {
			tcpConn.Close()
			switch resp.ReplyCode {
			case socks5.ReplyCodeNetworkUnreachable,
				socks5.ReplyCodeHostUnreachable,
				socks5.ReplyCodeConnectionRefused,
				socks5.ReplyCodeTTLExpired:
				return nil, dialDestinationFault, err
			}
			return nil, dialProxyFault, err
		}
		_ = tcpConn.SetDeadline(time.Time{})
		return tcpConn, dialOK, nil
	case scanner.ProtoHTTP:
		return h.handshakeHTTP(ctx, tcpConn, destination)
	default:
		tcpConn.Close()
		return nil, dialProxyFault, E.New("tooska: unsupported endpoint protocol ", proto)
	}
}

// handshakeHTTP performs CONNECT over an already-dialled conn. Builds
// the request manually so the conn isn't hijacked by net/http, and
// preserves any bytes the proxy pipelined after the 200 status.
func (h *Outbound) handshakeHTTP(ctx context.Context, conn net.Conn, destination M.Socksaddr) (net.Conn, dialOutcome, error) {
	target := destination.String()
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: target},
		Host:   target,
		Header: http.Header{},
	}
	req.Header.Set("User-Agent", "tooska/1.0")
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, dialProxyFault, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, dialProxyFault, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		outcome := dialProxyFault
		switch resp.StatusCode {
		case http.StatusBadGateway, http.StatusGatewayTimeout:
			outcome = dialDestinationFault
		}
		return nil, outcome, E.New("tooska: http connect ", resp.Status)
	}
	_ = conn.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		conn = &bufferedConn{Conn: conn, r: br}
	}
	return conn, dialOK, nil
}

// bufferedConn drains bytes that bufio.Reader pulled past the CONNECT
// 200-OK status before falling back to the underlying conn.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// kickRescanOnConnect satisfies "loop on every connect" — fires one
// background sweep per dial. The scanGate is checked lock-free first so
// we do not pay the cost of spawning a goroutine when one is already in
// flight.
func (h *Outbound) kickRescanOnConnect() {
	if h.scanGate.busy() {
		return
	}
	go h.runScan(h.ctx, "post-connect")
}

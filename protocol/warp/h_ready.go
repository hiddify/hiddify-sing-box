package warp

import (
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
)

// warpKeepalive is the keepalive of the WARP peer, in seconds, as the WARP clients use: it
// keeps the handshake fresh while the path works, and the first handshake starts at once.
const warpKeepalive = 25

// firstHandshakeWait is how long a new endpoint has to complete its first handshake before
// the next port is tried.
var firstHandshakeWait = 10 * time.Second

// handshakeFresh reports whether the peer answered within staleHandshake: WireGuard renews the
// handshake every two minutes while packets flow, and the keepalive keeps them flowing.
func handshakeFresh(inner adapter.Endpoint) bool {
	if _, isGetter := inner.(interface{ IpcGet() (string, error) }); !isGetter {
		return inner.IsReady()
	}
	lastHandshake, _ := peerStatus(inner)
	return !lastHandshake.IsZero() && time.Since(lastHandshake) < staleHandshake
}

// rotatePorts runs when the scanner is off and no server_port is set: when an endpoint does
// not complete a handshake, the next of the profile's ports is tried. A port that does not
// answer on a network was used forever before.
func (w *WARPEndpoint) rotatePorts(config *C.WARPConfig, address string, ports []uint16, current int) {
	connectedAt := time.Now()
	wait := firstHandshakeWait
	for {
		select {
		case <-w.done:
			return
		case <-w.ctx.Done():
			return
		case <-time.After(wait):
		}
		inner := w.currentEndpoint()
		if inner == nil {
			return
		}
		lastHandshake, _ := peerStatus(inner)
		if lastHandshake.After(connectedAt) && time.Since(lastHandshake) < staleHandshake {
			wait = failoverInterval // answering: check again later
			continue
		}
		current = (current + 1) % len(ports)
		replacement, err := w.newInner(config, address, ports[current])
		if err != nil {
			w.logger.ErrorContext(w.ctx, E.Cause(err, "WARP: replace endpoint"))
			return
		}
		select {
		case <-w.done:
			adapter.CloseLate(w.scope, replacement)
			return
		default:
		}
		w.mtx.Lock()
		old := w.endpoint
		w.endpoint = replacement
		w.mtx.Unlock()
		adapter.CloseLate(w.scope, old)
		w.logger.InfoContext(w.ctx, "WARP: no handshake, trying port ", ports[current])
		connectedAt = time.Now()
		wait = firstHandshakeWait
	}
}

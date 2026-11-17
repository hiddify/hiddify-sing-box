// Package peerfallback moves a WireGuard (or AmneziaWG) tunnel with a single peer to the peer's
// other addresses when the one in use does not answer.
//
// A peer can often be reached at more than one address (WARP at IPv4 and IPv6 ones), and the path
// may carry only some of them: a network or a proxy without IPv6, or a tunnel too small for IPv6's
// larger packets. The tunnel starts with the peer's own address. When packets went out but no
// handshake came back within Wait, it sends to the next address, and so on in turn. An idle tunnel
// sends nothing and is left alone. When the path changes (the network, or the detour's
// connection), it starts again from the peer's own address, the preferred one.
package peerfallback

import (
	"bufio"
	"context"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing/common/logger"
)

// Wait is how long an address that was sent to has to answer, and Interval how often it is
// checked; variables for tests.
var (
	Wait     = 15 * time.Second
	Interval = 5 * time.Second
)

type Options struct {
	Logger logger.Logger
	// Addresses are the peer's own address, then the fallback ones.
	Addresses []netip.AddrPort
	// Status is the latest handshake (zero for none) and the bytes sent; see ParseStatus.
	Status func() (handshake time.Time, tx uint64)
	// Move sends to address from now on. It reports whether the move makes the tunnel's connection
	// be made again, which reports a path change that is then not taken as one.
	Move func(address netip.AddrPort) (reconnects bool)
}

type Fallback struct {
	options Options

	// moveAccess is held while a move is decided and made. Move goes into the tunnel's device
	// (it sets the peer's address, makes the connection again and starts a handshake), so only
	// Check and PathChanged, which run on goroutines of their own, wait for it. Close does not:
	// it waited behind a move whose device was stuck on a stalled detour, and the endpoint could
	// not close.
	moveAccess sync.Mutex

	access   sync.Mutex // the fields below
	cancel   context.CancelFunc
	closed   bool
	index    int
	since    time.Time // the address in use was set
	sinceTx  uint64    // and the bytes sent then
	answered bool      // a handshake came back since
	moving   bool      // the connection is made again because of a move
}

// New is nil without fallback addresses; the methods of a nil Fallback do nothing.
func New(options Options) *Fallback {
	if len(options.Addresses) < 2 {
		return nil
	}
	return &Fallback{options: options, since: time.Now()}
}

// Start checks the address in use every few seconds, until ctx ends or Close.
func (f *Fallback) Start(ctx context.Context) {
	if f == nil {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	f.access.Lock()
	if f.closed {
		f.access.Unlock()
		cancel()
		return
	}
	f.cancel = cancel
	f.access.Unlock()
	go func() {
		ticker := time.NewTicker(Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				f.Check()
			}
		}
	}()
}

// Close stops the checks. It does not wait for a move that is on its way; no move starts after it.
func (f *Fallback) Close() {
	if f == nil {
		return
	}
	f.access.Lock()
	f.closed = true
	cancel := f.cancel
	f.access.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Check moves to the next address when the one in use was sent to but did not answer.
func (f *Fallback) Check() {
	if f == nil {
		return
	}
	handshake, tx := f.options.Status()
	f.moveAccess.Lock()
	defer f.moveAccess.Unlock()
	f.access.Lock()
	if f.closed {
		f.access.Unlock()
		return
	}
	if f.answered || handshake.After(f.since) {
		f.answered = true
		f.access.Unlock()
		return
	}
	if time.Since(f.since) < Wait || tx == f.sinceTx {
		f.access.Unlock()
		return
	}
	failed := f.options.Addresses[f.index]
	f.index = (f.index + 1) % len(f.options.Addresses)
	address := f.options.Addresses[f.index]
	f.since, f.sinceTx, f.answered = time.Now(), tx, false
	f.access.Unlock()
	f.options.Logger.Info("no handshake with ", failed, "; trying ", address)
	f.move(address)
}

// PathChanged starts again from the peer's own address. It reports whether the tunnel's
// connection is made again for it, which reports the path change once more. A path change that
// a move caused is only noted.
func (f *Fallback) PathChanged() bool {
	if f == nil {
		return false
	}
	_, tx := f.options.Status()
	f.moveAccess.Lock() // after a move on its way: the connection it makes is not a path change
	defer f.moveAccess.Unlock()
	f.access.Lock()
	if f.closed {
		f.access.Unlock()
		return false
	}
	if f.moving {
		f.moving = false
		f.access.Unlock()
		return false
	}
	f.since, f.sinceTx, f.answered = time.Now(), tx, false // the first address, on a new path
	if f.index == 0 {
		f.access.Unlock()
		return false
	}
	f.index = 0
	address := f.options.Addresses[0]
	f.access.Unlock()
	f.options.Logger.Debug("the path changed; trying ", address, " again")
	return f.move(address)
}

// move sends to address from now on; moveAccess is held, access is not.
func (f *Fallback) move(address netip.AddrPort) bool {
	reconnects := f.options.Move(address)
	f.access.Lock()
	f.moving = reconnects
	f.access.Unlock()
	return reconnects
}

// ParseStatus reads the latest handshake with any peer and the bytes sent to all from a
// WireGuard device's UAPI state (IpcGet).
func ParseStatus(state string) (time.Time, uint64) {
	var (
		latest  time.Time
		seconds int64
		tx      uint64
	)
	scanner := bufio.NewScanner(strings.NewReader(state))
	for scanner.Scan() {
		key, value, _ := strings.Cut(scanner.Text(), "=")
		switch key {
		case "last_handshake_time_sec":
			seconds, _ = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			nanoseconds, _ := strconv.ParseInt(value, 10, 64)
			if handshake := time.Unix(seconds, nanoseconds); (seconds > 0 || nanoseconds > 0) && handshake.After(latest) {
				latest = handshake
			}
		case "tx_bytes":
			bytes, _ := strconv.ParseUint(value, 10, 64)
			tx += bytes
		}
	}
	return latest, tx
}

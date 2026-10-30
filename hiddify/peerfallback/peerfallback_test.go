package peerfallback

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

type fake struct {
	handshake time.Time
	tx        uint64
	moves     []netip.AddrPort
	reconnect bool
}

func newFake() (*Fallback, *fake) {
	state := &fake{reconnect: true}
	f := New(Options{
		Logger:    logger.NOP(),
		Addresses: []netip.AddrPort{netip.MustParseAddrPort("162.159.192.1:2408"), netip.MustParseAddrPort("[2606:4700:d0::1]:2408")},
		Status:    func() (time.Time, uint64) { return state.handshake, state.tx },
		Move: func(address netip.AddrPort) bool {
			state.moves = append(state.moves, address)
			return state.reconnect
		},
	})
	return f, state
}

// An address that was sent to and gave no handshake for Wait is left for the next one; an idle
// one, or one that answered, is kept.
func TestCheck(t *testing.T) {
	f, state := newFake()
	f.since = time.Now().Add(-Wait - time.Second)
	f.Check()
	if len(state.moves) != 0 {
		t.Fatal("moved while idle")
	}
	state.tx = 148
	f.Check()
	if len(state.moves) != 1 || state.moves[0].Addr().Is4() {
		t.Fatalf("no handshake: moves %v", state.moves)
	}
	f.since = time.Now().Add(-Wait - time.Second)
	state.tx, state.handshake = 296, time.Now()
	f.Check()
	if len(state.moves) != 1 {
		t.Fatalf("answered, but moved: %v", state.moves)
	}
}

// After a path change it starts again from the peer's own address; the path change its own move
// causes is not taken as one.
func TestPathChanged(t *testing.T) {
	f, state := newFake()
	f.index = 1
	if !f.PathChanged() || len(state.moves) != 1 || !state.moves[0].Addr().Is4() {
		t.Fatalf("path change: moves %v", state.moves)
	}
	if f.PathChanged() {
		t.Fatal("the reconnect of the move was taken for a path change")
	}
	if f.PathChanged() || len(state.moves) != 1 {
		t.Fatal("already on the first address, but moved")
	}

	direct, state := newFake() // nothing to reconnect: only the peer's address changes
	state.reconnect = false
	direct.index = 1
	if direct.PathChanged() || direct.index != 0 || len(state.moves) != 1 {
		t.Fatalf("direct: index %d, moves %v", direct.index, state.moves)
	}
	if (*Fallback)(nil).PathChanged() || New(Options{Addresses: state.moves}) != nil {
		t.Error("no fallback, but it acts")
	}
}

func TestParseStatus(t *testing.T) {
	handshake, tx := ParseStatus("public_key=ab\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=5\ntx_bytes=100\nrx_bytes=7\npublic_key=cd\ntx_bytes=20\n")
	if handshake != time.Unix(1700000000, 5) || tx != 120 {
		t.Fatalf("%v %d", handshake, tx)
	}
}

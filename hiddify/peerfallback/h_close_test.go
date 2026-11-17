package peerfallback

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

// Close does not wait for a move. A move goes into the tunnel's device, and when the device was
// stuck sending through a stalled detour the move never returned: Close waited behind it, before
// the endpoint had closed the connections that would have freed the device.
func TestH_CloseDoesNotWaitForAMove(t *testing.T) {
	moving, release := make(chan struct{}), make(chan struct{})
	tx := uint64(148)
	moves := 0
	f := New(Options{
		Logger:    logger.NOP(),
		Addresses: []netip.AddrPort{netip.MustParseAddrPort("162.159.192.1:2408"), netip.MustParseAddrPort("[2606:4700:d0::1]:2408")},
		Status:    func() (time.Time, uint64) { return time.Time{}, tx },
		Move: func(netip.AddrPort) bool {
			moves++
			close(moving)
			<-release
			return true
		},
	})
	f.since = time.Now().Add(-Wait - time.Second)
	checked := make(chan struct{})
	go func() {
		f.Check()
		close(checked)
	}()
	select {
	case <-moving:
	case <-time.After(3 * time.Second):
		t.Fatal("no move")
	}

	closed := make(chan struct{})
	go func() {
		f.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("Close waits for the move")
	}
	close(release)
	<-checked

	// nothing moves after Close
	f.access.Lock()
	f.since, f.sinceTx = time.Now().Add(-Wait-time.Second), 0
	f.access.Unlock()
	f.Check()
	if f.PathChanged() || moves != 1 {
		t.Fatalf("moved after Close: %d moves", moves)
	}
}

package psiphon

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/sagernet/sing-box/log"
	"github.com/stretchr/testify/require"
)

// The last instance stops listening while tunnel-core writes notices, as a controller does while
// it stops. The hub was removed under its own lock, which needs tunnel-core's notice lock, while
// a notice being written held that lock and waited for the hub's: Close deadlocked.
func TestH_NoticeHubCloseWhileNoticesAreWritten(t *testing.T) {
	p := &Psiphon{logger: log.NewNOPFactory().Logger(), ctx: context.Background()}
	var stop atomic.Bool
	emitted := make(chan struct{})
	go func() {
		defer close(emitted)
		for !stop.Load() {
			psiphon.NoticeTunnels(0)
		}
	}()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 20000 {
			if err := listenNotices(p, func(NoticeEvent) {}); err != nil {
				t.Error(err)
				return
			}
			stopListeningNotices(p)
		}
	}()
	select {
	case <-done:
		stop.Store(true)
		<-emitted
	case <-time.After(30 * time.Second):
		t.Fatal("deadlock: listening and stopping got stuck while notices were written")
	}
}

// A closed outbound does not start its controller again: run lived on the box's context, which
// a hot reload or a lazy unload does not end.
func TestH_ClosedOutboundStopsRunning(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, closeOutbound := context.WithCancel(ctx)
	outbound := &Outbound{
		ctx:     ctx,
		cancel:  closeOutbound,
		logger:  log.NewNOPFactory().Logger(),
		psiphon: &Psiphon{logger: log.NewNOPFactory().Logger(), ctx: ctx, config: &psiphon.Config{}},
		runDone: make(chan struct{}),
	}
	go func() {
		defer close(outbound.runDone)
		outbound.run()
	}()
	closed := make(chan struct{})
	go func() {
		outbound.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not end run")
	}
	require.Error(t, ctx.Err())
}

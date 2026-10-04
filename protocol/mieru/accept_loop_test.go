package mieru

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	mierumodel "github.com/enfein/mieru/v3/apis/model"
	mieruserver "github.com/enfein/mieru/v3/apis/server"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
	"github.com/stretchr/testify/require"
)

// failingAcceptServer stands in for a mieru server whose Accept keeps
// failing immediately while the server itself still reports as running. That
// is the state the accept loop used to spin in.
type failingAcceptServer struct {
	mieruserver.Server

	calls   atomic.Int64
	running atomic.Bool
}

func newFailingAcceptServer() *failingAcceptServer {
	s := &failingAcceptServer{}
	s.running.Store(true)
	return s
}

func (s *failingAcceptServer) Accept() (net.Conn, *mierumodel.Request, error) {
	s.calls.Add(1)
	return nil, nil, net.ErrClosed
}

func (s *failingAcceptServer) IsRunning() bool {
	return s.running.Load()
}

// flakyAcceptServer fails a fixed number of times, then hands out that many
// connections and finally blocks, so a test can observe whether the loop kept
// serving after transient failures.
type flakyAcceptServer struct {
	mieruserver.Server

	remaining atomic.Int64
	granted   atomic.Int64
	running   atomic.Bool
	release   chan struct{}
}

func newFlakyAcceptServer(failures, served int64) *flakyAcceptServer {
	s := &flakyAcceptServer{
		release: make(chan struct{}),
	}
	s.remaining.Store(failures)
	s.running.Store(true)
	s.granted.Store(served)
	return s
}

func (s *flakyAcceptServer) Accept() (net.Conn, *mierumodel.Request, error) {
	if s.remaining.Add(-1) >= 0 {
		return nil, nil, net.ErrClosed
	}
	if s.granted.Add(-1) >= 0 {
		conn, peer := net.Pipe()
		go func() {
			<-s.release
			peer.Close()
		}()
		return conn, &mierumodel.Request{}, nil
	}
	<-s.release
	return nil, nil, net.ErrClosed
}

func (s *flakyAcceptServer) IsRunning() bool {
	return s.running.Load()
}

func newTestInbound(ctx context.Context, server mieruserver.Server) *Inbound {
	return &Inbound{
		Adapter: inbound.NewAdapter("mieru-in", "mieru-in"),
		ctx:     ctx,
		logger:  log.NewNOPFactory().Logger(),
		server:  server,
	}
}

func runAcceptLoop(ctx context.Context, in *Inbound) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		in.acceptLoop()
		close(done)
	}()
	return done
}

func TestAcceptLoopBacksOffOnPersistentError(t *testing.T) {
	t.Parallel()
	server := newFailingAcceptServer()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runAcceptLoop(ctx, newTestInbound(ctx, server))

	// Long enough that an unthrottled loop would have produced millions of
	// calls, and several times the initial backoff.
	time.Sleep(500 * time.Millisecond)
	require.Less(t, server.calls.Load(), int64(20),
		"accept loop must throttle a persistently failing Accept")

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("acceptLoop did not return after context cancellation")
	}
}

func TestAcceptLoopKeepsServingAfterTransientErrors(t *testing.T) {
	t.Parallel()
	const served = 3
	server := newFlakyAcceptServer(served, served)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runAcceptLoop(ctx, newTestInbound(ctx, server))

	require.Eventually(t, func() bool {
		return server.granted.Load() <= 0
	}, 10*time.Second, 10*time.Millisecond, "accept loop should keep serving after transient failures")

	cancel()
	close(server.release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("acceptLoop did not return after context cancellation")
	}
}
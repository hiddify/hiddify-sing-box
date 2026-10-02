package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

func hNewBase() *BaseTransport {
	return NewBaseTransport(dns.NewTransportAdapter(C.DNSTypeUDP, "base", nil), log.NewNOPFactory().NewLogger("base"))
}

func TestH_BaseTransportLifecycle(t *testing.T) {
	t.Parallel()
	base := hNewBase()
	require.Equal(t, StateNew, base.State())
	require.False(t, base.BeginQuery())
	require.NoError(t, base.SetStarted())
	require.NoError(t, base.SetStarted())
	require.Equal(t, StateStarted, base.State())
	require.NoError(t, base.CloseContext().Err())

	require.True(t, base.BeginQuery())
	base.EndQuery()
	base.EndQuery()

	require.NoError(t, base.Close())
	require.Equal(t, StateClosed, base.State())
	require.Error(t, base.CloseContext().Err())
	require.False(t, base.BeginQuery())
	require.ErrorIs(t, base.SetStarted(), ErrTransportClosed)
	require.NoError(t, base.Close())
}

func TestH_BaseTransportShutdownBeforeStart(t *testing.T) {
	t.Parallel()
	base := hNewBase()
	require.NoError(t, base.Shutdown(context.Background()))
	require.Equal(t, StateClosed, base.State())
	require.Error(t, base.CloseContext().Err())
	require.ErrorIs(t, base.SetStarted(), ErrTransportClosed)
}

func TestH_BaseTransportShutdownWaitsForQueries(t *testing.T) {
	t.Parallel()
	base := hNewBase()
	require.NoError(t, base.SetStarted())
	require.True(t, base.BeginQuery())
	require.True(t, base.BeginQuery())

	done := make(chan error, 1)
	go func() {
		done <- base.Shutdown(context.Background())
	}()
	require.Eventually(t, func() bool { return base.State() == StateClosing }, time.Second, time.Millisecond)
	require.False(t, base.BeginQuery())
	require.Eventually(t, func() bool { return base.CloseContext().Err() != nil }, time.Second, time.Millisecond)

	base.EndQuery()
	select {
	case <-done:
		t.Fatal("shutdown returned with a query still in flight")
	case <-time.After(20 * time.Millisecond):
	}
	base.EndQuery()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("shutdown did not complete")
	}
	require.Equal(t, StateClosed, base.State())
}

func TestH_BaseTransportShutdownTimeout(t *testing.T) {
	t.Parallel()
	base := hNewBase()
	require.NoError(t, base.SetStarted())
	require.True(t, base.BeginQuery())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, base.Shutdown(ctx), context.DeadlineExceeded)
	require.Equal(t, StateClosed, base.State())
	base.EndQuery()
}

type hConn struct {
	id     int
	closed atomic.Bool
	reset  atomic.Bool
}

func hConnCallbacks() ConnectorCallbacks[*hConn] {
	return ConnectorCallbacks[*hConn]{
		IsClosed: func(c *hConn) bool { return c.closed.Load() || c.reset.Load() },
		Close:    func(c *hConn) { c.closed.Store(true) },
		Reset:    func(c *hConn) { c.reset.Store(true) },
	}
}

func hTestCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestH_ConnectorReusesConnection(t *testing.T) {
	t.Parallel()
	var dials atomic.Int32
	connector := NewConnector(context.Background(), func(ctx context.Context) (*hConn, error) {
		return &hConn{id: int(dials.Add(1))}, nil
	}, hConnCallbacks())
	first, err := connector.Get(hTestCtx(t))
	require.NoError(t, err)
	second, err := connector.Get(hTestCtx(t))
	require.NoError(t, err)
	require.Same(t, first, second)
	require.EqualValues(t, 1, dials.Load())

	first.closed.Store(true)
	third, err := connector.Get(hTestCtx(t))
	require.NoError(t, err)
	require.NotSame(t, first, third)
	require.EqualValues(t, 2, dials.Load())

	connector.Reset()
	require.True(t, third.reset.Load())
	fourth, err := connector.Get(hTestCtx(t))
	require.NoError(t, err)
	require.Equal(t, 3, fourth.id)

	require.NoError(t, connector.Close())
	require.True(t, fourth.closed.Load())
	_, err = connector.Get(hTestCtx(t))
	require.ErrorIs(t, err, ErrTransportClosed)
	require.NoError(t, connector.Close())
}

func TestH_ConnectorSingleflight(t *testing.T) {
	t.Parallel()
	var dials atomic.Int32
	release := make(chan struct{})
	connector := NewConnector(context.Background(), func(ctx context.Context) (*hConn, error) {
		dials.Add(1)
		<-release
		return &hConn{}, nil
	}, hConnCallbacks())

	const workers = 8
	results := make([]*hConn, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := connector.Get(hTestCtx(t))
			require.NoError(t, err)
			results[i] = conn
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	require.EqualValues(t, 1, dials.Load())
	for _, conn := range results {
		require.Same(t, results[0], conn)
	}
}

func TestH_ConnectorDialError(t *testing.T) {
	t.Parallel()
	dialErr := errors.New("dial failed")
	var dials atomic.Int32
	connector := NewConnector(context.Background(), func(ctx context.Context) (*hConn, error) {
		if dials.Add(1) == 1 {
			return nil, dialErr
		}
		return &hConn{}, nil
	}, hConnCallbacks())
	_, err := connector.Get(hTestCtx(t))
	require.ErrorIs(t, err, dialErr)
	conn, err := connector.Get(hTestCtx(t))
	require.NoError(t, err)
	require.NotNil(t, conn)
}

func TestH_ConnectorRecursiveDial(t *testing.T) {
	t.Parallel()
	var connector *Connector[*hConn]
	connector = NewConnector(context.Background(), func(ctx context.Context) (*hConn, error) {
		_, err := connector.Get(ctx)
		return nil, err
	}, hConnCallbacks())
	_, err := connector.Get(hTestCtx(t))
	require.ErrorIs(t, err, errRecursiveConnectorDial)
}

func TestH_ConnectorContextCanceledDuringDial(t *testing.T) {
	t.Parallel()
	dialed := make(chan *hConn, 1)
	connector := NewConnector(context.Background(), func(ctx context.Context) (*hConn, error) {
		<-ctx.Done()
		conn := &hConn{}
		dialed <- conn
		return conn, nil
	}, hConnCallbacks())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := connector.Get(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	select {
	case conn := <-dialed:
		require.Eventually(t, conn.closed.Load, time.Second, time.Millisecond)
	case <-time.After(time.Second):
		t.Fatal("dial did not observe cancellation")
	}

	_, err = connector.Get(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestH_ConnectorCloseDuringDial(t *testing.T) {
	t.Parallel()
	closeCtx, closeCancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	connector := NewConnector(closeCtx, func(ctx context.Context) (*hConn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}, hConnCallbacks())
	go func() {
		<-started
		closeCancel()
	}()
	_, err := connector.Get(hTestCtx(t))
	require.ErrorIs(t, err, ErrTransportClosed)
}

func TestH_ConnectionWrapper(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer server.Close()
	conn := WrapConnection(client)
	require.False(t, conn.IsClosed())
	require.NoError(t, conn.CloseError())

	connector := NewSingleflightConnector(context.Background(), func(ctx context.Context) (*Connection, error) {
		return conn, nil
	})
	got, err := connector.Get(hTestCtx(t))
	require.NoError(t, err)
	require.Same(t, conn, got)

	connector.Reset()
	require.True(t, conn.IsClosed())
	require.ErrorIs(t, conn.CloseError(), ErrConnectionReset)
	select {
	case <-conn.Done():
	default:
		t.Fatal("done channel not closed")
	}
	require.NoError(t, conn.CloseWithError(errors.New("ignored")))
	require.ErrorIs(t, conn.CloseError(), ErrConnectionReset)

	other := WrapConnection(server)
	require.NoError(t, other.Close())
	require.ErrorIs(t, other.CloseError(), ErrTransportClosed)
}

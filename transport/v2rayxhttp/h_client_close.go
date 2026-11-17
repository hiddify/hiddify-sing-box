package xhttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
	"golang.org/x/net/http2"
)

// hClientState is what a DefaultDialerClient keeps to close its connections and to dial the
// first upload's connection ahead.
type hClientState struct {
	connAccess sync.Mutex
	// hClosed is set by Close. It is not closed, which the stream goroutines also set when a
	// request fails, to mean only that the client is not to be used again: on a client several
	// connections share, a failed request then closed every connection dialled after it.
	hClosed atomic.Bool
	conns   map[*hConn]struct{}   // the TCP connections it dialled and has not closed
	warm    atomic.Pointer[hWarm] // an upload connection being dialled ahead
}

// hConn is a connection a client dialled; the client forgets it when it is closed.
type hConn struct {
	net.Conn
	owner *DefaultDialerClient
	once  sync.Once
}

func (c *hConn) Close() error {
	c.once.Do(func() {
		c.owner.connAccess.Lock()
		delete(c.owner.conns, c)
		c.owner.connAccess.Unlock()
	})
	return c.Conn.Close()
}

func (c *hConn) Upstream() any {
	return c.Conn
}

// hTrack remembers a connection the client dialled, so that Close can close it.
func (c *DefaultDialerClient) hTrack(conn net.Conn) net.Conn {
	tracked := &hConn{Conn: conn, owner: c}
	c.connAccess.Lock()
	if c.hClosed.Load() {
		c.connAccess.Unlock()
		conn.Close()
		return tracked
	}
	if c.conns == nil {
		c.conns = make(map[*hConn]struct{})
	}
	c.conns[tracked] = struct{}{}
	c.connAccess.Unlock()
	return tracked
}

// Close closes the client's connections to the server: an HTTP/3 one with its QUIC connection
// and socket, an HTTP/2 or HTTP/1.1 one with its TCP connection. Without it they stayed open
// after the outbound was closed, an HTTP/2 one for five idle minutes and an HTTP/3 one, which
// sends a keep-alive every ten seconds, for up to fifty.
func (c *DefaultDialerClient) Close() error {
	c.connAccess.Lock()
	c.hClosed.Store(true)
	conns := c.conns
	c.conns = nil
	c.connAccess.Unlock()
	switch transport := c.client.Transport.(type) {
	case *http3.Transport:
		transport.Close()
	case *http2.Transport:
		transport.CloseIdleConnections()
	case *http.Transport:
		transport.CloseIdleConnections()
	}
	for conn := range conns {
		conn.Conn.Close()
	}
	return nil
}

// hWarm is an upload connection dialled ahead: done is closed when the dial has ended, and conn
// is the connection until the first upload takes it.
type hWarm struct {
	done chan struct{}
	conn atomic.Pointer[H1Conn]
}

// hWarmUpload dials the connection of the first upload while the download's is being dialled.
//
// Over HTTP/1.1 the uploads of packet-up go on a connection of their own. It was dialled only
// when the first upload was sent, after the download's connection was up: two TCP and TLS
// handshakes one after the other before the first byte reached the server. Dialled side by side,
// a new connection starts two round trips sooner.
func hWarmUpload(ctx context.Context, client DialerClient) {
	c, isDefault := client.(*DefaultDialerClient)
	if !isDefault || c.httpVersion != "1.1" {
		return
	}
	if pooled := c.uploadRawPool.Get(); pooled != nil {
		c.uploadRawPool.Put(pooled) // one waits there already
		return
	}
	warm := &hWarm{done: make(chan struct{})}
	if !c.warm.CompareAndSwap(nil, warm) {
		return // one is on its way, or ready and not taken yet
	}
	ctx = context.WithoutCancel(ctx) // the upload's, as its own dial is: not the dial context's
	go func() {
		defer close(warm.done)
		conn, err := c.dialUploadConn(ctx)
		if err != nil {
			c.warm.CompareAndSwap(warm, nil)
			return // the upload dials for itself, and reports the error
		}
		warm.conn.Store(NewH1Conn(conn))
	}()
}

// hTakeWarm returns the upload connection that was dialled ahead, waiting for it when it is
// still on its way, or nil when there is none. It is handed over here and not through the pool,
// which may drop what is put into it.
func (c *DefaultDialerClient) hTakeWarm(ctx context.Context) any {
	warm := c.warm.Load()
	if warm == nil {
		return nil
	}
	select {
	case <-warm.done:
	case <-ctx.Done():
		return nil
	}
	c.warm.CompareAndSwap(warm, nil)
	if conn := warm.conn.Swap(nil); conn != nil {
		return conn
	}
	return nil
}

// hWrapH3 makes the errors with which an HTTP/3 stream ends when it is closed known as such
// (net.ErrClosed), as baderror.WrapH2 does for HTTP/2: a download the application stopped was
// logged as an error, "H3_REQUEST_CANCELLED (local)".
func hWrapH3(err error) error {
	if err == nil {
		return nil
	}
	var (
		h3Err        *http3.Error
		streamErr    *quic.StreamError
		appErr       *quic.ApplicationError
		transportErr *quic.TransportError
	)
	if errors.As(err, &h3Err) || errors.As(err, &streamErr) || errors.As(err, &appErr) || errors.As(err, &transportErr) {
		return qtls.WrapError(err)
	}
	return err
}

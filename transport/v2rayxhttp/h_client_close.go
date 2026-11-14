package xhttp

import (
	"errors"
	"net"
	"net/http"
	"sync"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
	"golang.org/x/net/http2"
)

// hClientState is what a DefaultDialerClient keeps to close its connections.
type hClientState struct {
	connAccess sync.Mutex
	conns      map[*hConn]struct{} // the TCP connections it dialled and has not closed
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
	if c.closed.Load() {
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
	c.closed.Store(true)
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

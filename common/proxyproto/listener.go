package proxyproto

import (
	std_bufio "bufio"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/pires/go-proxyproto"
)

// defaultHeaderTimeout bounds how long a connection may take to send its PROXY header.
const defaultHeaderTimeout = 10 * time.Second

// Listener reads the PROXY protocol header (v1 or v2) of each accepted connection and reports
// the addresses it carries as the connection's addresses. Headers are read concurrently, so a
// slow or silent client never blocks the others; a connection without a valid header is closed,
// unless AcceptNoHeader is set (then it is used as it is). //H restored
type Listener struct {
	net.Listener
	acceptNoHeader bool
	headerTimeout  time.Duration
	conns          chan net.Conn
	errors         chan error
	done           chan struct{}
	closeOnce      sync.Once
}

func NewListener(listener net.Listener, acceptNoHeader bool) *Listener {
	return newListener(listener, acceptNoHeader, defaultHeaderTimeout)
}

func newListener(listener net.Listener, acceptNoHeader bool, headerTimeout time.Duration) *Listener {
	l := &Listener{
		Listener:       listener,
		acceptNoHeader: acceptNoHeader,
		headerTimeout:  headerTimeout,
		conns:          make(chan net.Conn),
		errors:         make(chan error),
		done:           make(chan struct{}),
	}
	go l.loopAccept()
	return l
}

func (l *Listener) loopAccept() {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			select {
			case l.errors <- err:
			case <-l.done:
				return
			}
			//nolint:staticcheck
			if netError, isNetError := err.(net.Error); isNetError && netError.Temporary() {
				continue
			}
			return
		}
		go l.readHeader(conn)
	}
}

func (l *Listener) readHeader(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(l.headerTimeout))
	bufReader := std_bufio.NewReader(conn)
	header, err := proxyproto.Read(bufReader)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil && !(l.acceptNoHeader && err == proxyproto.ErrNoProxyProtocol) {
		conn.Close()
		return
	}
	if bufReader.Buffered() > 0 {
		cache := buf.NewSize(bufReader.Buffered())
		_, err = cache.ReadFullFrom(bufReader, cache.FreeLen())
		if err != nil {
			cache.Release()
			conn.Close()
			return
		}
		conn = bufio.NewCachedConn(conn, cache)
	}
	if header != nil && header.SourceAddr != nil && header.DestinationAddr != nil {
		conn = &bufio.AddrConn{
			Conn:        conn,
			Source:      M.SocksaddrFromNet(header.SourceAddr).Unwrap(),
			Destination: M.SocksaddrFromNet(header.DestinationAddr).Unwrap(),
		}
	}
	select {
	case l.conns <- conn:
	case <-l.done:
		conn.Close()
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case err := <-l.errors:
		return nil, err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *Listener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.Listener.Close()
}

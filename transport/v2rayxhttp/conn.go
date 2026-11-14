package xhttp

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/xray/signal/done"
	"github.com/sagernet/sing/common/baderror" //H
)

type splitConn struct {
	writer     io.WriteCloser
	reader     io.ReadCloser
	remoteAddr net.Addr
	localAddr  net.Addr
	onClose    func()
}

// Write and Read wrap HTTP/2 stream errors (baderror.WrapH2), as the gRPC and HTTP transports do:
// HTTP/2 or TLS over this conn, such as an HTTPS URL test, would otherwise get the bare stream error
// back from its framer and keep reading, spinning a core for good. //H
func (c *splitConn) Write(b []byte) (int, error) {
	n, err := c.writer.Write(b)
	return n, baderror.WrapH2(err) //H
}

func (c *splitConn) Read(b []byte) (int, error) {
	n, err := c.reader.Read(b)
	return n, baderror.WrapH2(err) //H
}

func (c *splitConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}

	err := c.writer.Close()
	var err2 error       //H
	if c.reader != nil { //H: a dial that failed has no reader yet
		err2 = c.reader.Close() //H
	} //H
	if err != nil {
		return err
	}

	if err2 != nil {
		return err2
	}

	return nil
}

func (c *splitConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *splitConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *splitConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *splitConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *splitConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

// NeedAdditionalReadDeadline makes callers wrap the conn for read deadlines, as for gRPC and HTTP
func (c *splitConn) NeedAdditionalReadDeadline() bool {
	return true
}

type H1Conn struct {
	UnreadedResponsesCount int
	RespBufReader          *bufio.Reader
	net.Conn
}

func NewH1Conn(conn net.Conn) *H1Conn {
	return &H1Conn{
		RespBufReader: bufio.NewReader(conn),
		Conn:          conn,
	}
}

type httpServerConn struct {
	sync.Mutex
	*done.Instance
	io.Reader // no need to Close request.Body
	http.ResponseWriter
}

func (c *httpServerConn) Write(b []byte) (int, error) {
	c.Lock()
	defer c.Unlock()
	if c.Done() {
		return 0, io.ErrClosedPipe
	}
	n, err := c.ResponseWriter.Write(b)
	if err == nil {
		c.ResponseWriter.(http.Flusher).Flush()
	}
	return n, err
}

func (c *httpServerConn) Close() error {
	c.Lock()
	defer c.Unlock()
	return c.Instance.Close()
}

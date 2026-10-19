package masque

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/http3"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	"golang.org/x/sync/semaphore"
)

type L4ClientOptions struct {
	Dialer               N.Dialer
	TLSConfig            aTLS.Config
	Endpoint             net.Addr
	UDPKeepalivePeriod   time.Duration
	UDPInitialPacketSize uint16
	HandshakeTimeout     time.Duration
	CongestionControl    func(conn *quic.Conn) congestion.CongestionControl
}

type L4Client struct {
	logger     logger.ContextLogger
	options    L4ClientOptions
	access     *semaphore.Weighted
	connection *l4Connection
	closed     bool
}

type l4Connection struct {
	packetConn net.PacketConn
	quicConn   *quic.Conn
	clientConn *http3.ClientConn
}

func NewL4Client(logger logger.ContextLogger, options L4ClientOptions) *L4Client {
	return &L4Client{
		logger:  logger,
		options: options,
		access:  semaphore.NewWeighted(1),
	}
}

func (c *L4Client) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, E.New("MASQUE L4 proxy mode does not support ", network)
	}
	connection, err := c.openConnection(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := connection.clientConn.OpenRequestStream(ctx)
	if err != nil {
		c.closeConnection(connection)
		return nil, err
	}
	address := destination.String()
	request, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+address, nil)
	if err != nil {
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		return nil, err
	}
	request.Host = address
	stop := context.AfterFunc(ctx, func() {
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	})
	var response *http.Response
	err = stream.SendRequestHeader(request)
	if err == nil {
		response, err = stream.ReadResponse()
	}
	if err == nil && !stop() {
		err = ctx.Err()
	}
	if err == nil && (response.StatusCode < 200 || response.StatusCode > 299) {
		err = E.New("CONNECT rejected with status ", response.StatusCode)
	}
	if err != nil {
		stop()
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		return nil, err
	}
	return &l4StreamConn{
		stream:   stream,
		quicConn: connection.quicConn,
	}, nil
}

func (c *L4Client) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("MASQUE L4 proxy mode does not support UDP")
}

func (c *L4Client) Close() error {
	_ = c.access.Acquire(context.Background(), 1)
	connection := c.connection
	c.connection = nil
	c.closed = true
	c.access.Release(1)
	if connection != nil {
		connection.Close()
	}
	return nil
}

func (c *L4Client) openConnection(ctx context.Context) (*l4Connection, error) {
	err := c.access.Acquire(ctx, 1)
	if err != nil {
		return nil, err
	}
	defer c.access.Release(1)
	if c.closed {
		return nil, net.ErrClosed
	}
	if c.connection != nil {
		if c.connection.quicConn.Context().Err() == nil {
			return c.connection, nil
		}
		c.connection.Close()
		c.connection = nil
	}
	dialCtx := ctx
	if c.options.HandshakeTimeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, c.options.HandshakeTimeout)
		defer cancel()
	}
	c.logger.InfoContext(ctx, "establishing MASQUE L4 proxy connection to ", c.options.Endpoint)
	packetConn, quicConn, err := dialQUIC(
		dialCtx,
		c.options.Dialer,
		c.options.TLSConfig,
		DefaultQuicConfig(c.options.UDPKeepalivePeriod, c.options.UDPInitialPacketSize),
		c.options.Endpoint,
		c.options.CongestionControl,
	)
	if err != nil {
		return nil, E.Cause(err, "connect MASQUE L4 proxy")
	}
	transport := &http3.Transport{}
	c.connection = &l4Connection{
		packetConn: packetConn,
		quicConn:   quicConn,
		clientConn: transport.NewClientConn(quicConn),
	}
	return c.connection, nil
}

func (c *L4Client) closeConnection(connection *l4Connection) {
	_ = c.access.Acquire(context.Background(), 1)
	if c.connection == connection {
		c.connection = nil
	}
	c.access.Release(1)
	connection.Close()
}

func (c *l4Connection) Close() {
	_ = c.clientConn.CloseWithError(0, "client closed")
	_ = c.packetConn.Close()
}

type l4StreamConn struct {
	stream   *http3.RequestStream
	quicConn *quic.Conn
}

func (c *l4StreamConn) Read(b []byte) (int, error) {
	return c.stream.Read(b)
}

func (c *l4StreamConn) Write(b []byte) (int, error) {
	return c.stream.Write(b)
}

func (c *l4StreamConn) Close() error {
	c.stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	return c.stream.Close()
}

func (c *l4StreamConn) LocalAddr() net.Addr {
	return c.quicConn.LocalAddr()
}

func (c *l4StreamConn) RemoteAddr() net.Addr {
	return c.quicConn.RemoteAddr()
}

func (c *l4StreamConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *l4StreamConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *l4StreamConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

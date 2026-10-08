package proxyproto

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/require"
)

func hListen(t *testing.T, acceptNoHeader bool) (*Listener, string) {
	t.Helper()
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { tcpListener.Close() })
	listener := NewListener(tcpListener, acceptNoHeader)
	t.Cleanup(func() { listener.Close() })
	return listener, tcpListener.Addr().String()
}

type hAcceptResult struct {
	conn net.Conn
	err  error
}

func hAcceptWith(t *testing.T, listener *Listener, address string, payload []byte) hAcceptResult {
	t.Helper()
	resultCh := make(chan hAcceptResult, 1)
	go func() {
		conn, err := listener.Accept()
		resultCh <- hAcceptResult{conn, err}
	}()
	client, err := net.DialTimeout("tcp", address, 2*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	_, err = client.Write(payload)
	require.NoError(t, err)
	if tcpConn, ok := client.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
	}
	select {
	case result := <-resultCh:
		if result.conn != nil {
			t.Cleanup(func() { result.conn.Close() })
			_ = result.conn.SetDeadline(time.Now().Add(3 * time.Second))
		}
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("accept timeout")
		return hAcceptResult{}
	}
}

// hRejected sends payload and expects the connection to be closed without being accepted.
func hRejected(t *testing.T, listener *Listener, address string, payload []byte) {
	t.Helper()
	acceptCh := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			acceptCh <- conn
		}
	}()
	client, err := net.DialTimeout("tcp", address, 2*time.Second)
	require.NoError(t, err)
	defer client.Close()
	_, err = client.Write(payload)
	require.NoError(t, err)
	if tcpConn, ok := client.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = client.Read(make([]byte, 1))
	require.Error(t, err, "the connection must be closed")
	require.False(t, errors.Is(err, os.ErrDeadlineExceeded), "the connection was not closed")
	select {
	case conn := <-acceptCh:
		conn.Close()
		t.Fatal("a connection without a valid header was accepted")
	case <-time.After(200 * time.Millisecond):
	}
}

func hHeaderBytes(t *testing.T, header *proxyproto.Header) []byte {
	t.Helper()
	data, err := header.Format()
	require.NoError(t, err)
	return data
}

func TestH_ListenerV1AndV2(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		version byte
		source  string
		dest    string
	}{
		{"v1-ipv4", 1, "192.0.2.10:12345", "198.51.100.20:443"},
		{"v1-ipv6", 1, "[2001:db8::10]:12345", "[2001:db8::20]:443"},
		{"v2-ipv4", 2, "192.0.2.10:12345", "198.51.100.20:443"},
		{"v2-ipv6", 2, "[2001:db8::10]:12345", "[2001:db8::20]:443"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			listener, address := hListen(t, false)
			source := net.TCPAddrFromAddrPort(netip.MustParseAddrPort(testCase.source))
			dest := net.TCPAddrFromAddrPort(netip.MustParseAddrPort(testCase.dest))
			header := proxyproto.HeaderProxyFromAddrs(testCase.version, source, dest)
			payload := append(hHeaderBytes(t, header), []byte("hello world")...)
			result := hAcceptWith(t, listener, address, payload)
			require.NoError(t, result.err)
			require.Equal(t, testCase.source, result.conn.RemoteAddr().String())
			require.Equal(t, testCase.dest, result.conn.LocalAddr().String())
			data, err := io.ReadAll(result.conn)
			require.NoError(t, err)
			require.Equal(t, "hello world", string(data))
		})
	}
}

func TestH_ListenerV2Local(t *testing.T) {
	t.Parallel()
	listener, address := hListen(t, false)
	header := &proxyproto.Header{Version: 2, Command: proxyproto.LOCAL, TransportProtocol: proxyproto.UNSPEC}
	result := hAcceptWith(t, listener, address, append(hHeaderBytes(t, header), 'x'))
	require.NoError(t, result.err)
	data, err := io.ReadAll(result.conn)
	require.NoError(t, err)
	require.Equal(t, "x", string(data))
}

func TestH_ListenerNoHeader(t *testing.T) {
	t.Parallel()
	listener, address := hListen(t, true)
	result := hAcceptWith(t, listener, address, []byte("GET / HTTP/1.1\r\n\r\n"))
	require.NoError(t, result.err)
	data, err := io.ReadAll(result.conn)
	require.NoError(t, err)
	require.Equal(t, "GET / HTTP/1.1\r\n\r\n", string(data))

	strict, strictAddress := hListen(t, false)
	hRejected(t, strict, strictAddress, []byte("GET / HTTP/1.1\r\n\r\n"))
}

func TestH_ListenerMalformedHeaders(t *testing.T) {
	t.Parallel()
	v2 := hHeaderBytes(t, proxyproto.HeaderProxyFromAddrs(2,
		&net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1},
		&net.TCPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 2}))
	badV2Version := append([]byte(nil), v2...)
	badV2Version[12] = 0x31
	truncatedV2 := v2[:len(v2)-3]
	payloads := map[string][]byte{
		"v1-bad-protocol":    []byte("PROXY TCP9 1.1.1.1 2.2.2.2 1 2\r\n"),
		"v1-bad-address":     []byte("PROXY TCP4 1.1.1 2.2.2.2 1 2\r\n"),
		"v1-family-mismatch": []byte("PROXY TCP4 2001:db8::1 2.2.2.2 1 2\r\n"),
		"v1-bad-port":        []byte("PROXY TCP4 1.1.1.1 2.2.2.2 99999 2\r\n"),
		"v1-missing-fields":  []byte("PROXY TCP4 1.1.1.1\r\n"),
		"v1-no-crlf":         []byte("PROXY TCP4 1.1.1.1 2.2.2.2 1 2"),
		"v2-bad-version":     badV2Version,
		"v2-truncated":       truncatedV2,
	}
	for name, payload := range payloads {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, acceptNoHeader := range []bool{false, true} {
				listener, address := hListen(t, acceptNoHeader)
				hRejected(t, listener, address, payload)
			}
		})
	}
}

type hPipeDialer struct {
	network     string
	destination M.Socksaddr
	conn        net.Conn
	err         error
}

func (d *hPipeDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.network = network
	d.destination = destination
	return d.conn, d.err
}

func (d *hPipeDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unsupported")
}

func hDialAndReadHeader(t *testing.T, ctx context.Context, destination M.Socksaddr) (*proxyproto.Header, error) {
	t.Helper()
	local, remote := net.Pipe()
	t.Cleanup(func() { local.Close(); remote.Close() })
	_ = remote.SetDeadline(time.Now().Add(2 * time.Second))
	dialer := &Dialer{Dialer: &hPipeDialer{conn: local}}
	type readResult struct {
		header *proxyproto.Header
		err    error
	}
	readCh := make(chan readResult, 1)
	go func() {
		header, err := proxyproto.Read(bufio.NewReader(remote))
		readCh <- readResult{header, err}
	}()
	conn, dialErr := dialer.DialContext(ctx, N.NetworkTCP, destination)
	if dialErr != nil {
		return nil, dialErr
	}
	require.Equal(t, local, conn)
	result := <-readCh
	return result.header, result.err
}

func TestH_DialerWritesV1Header(t *testing.T) {
	t.Parallel()
	ctx := adapter.WithContext(context.Background(), &adapter.InboundContext{
		Source: M.SocksaddrFrom(netip.MustParseAddr("192.0.2.33"), 4444),
	})
	header, err := hDialAndReadHeader(t, ctx, M.SocksaddrFrom(netip.MustParseAddr("198.51.100.1"), 80))
	require.NoError(t, err)
	require.Equal(t, byte(1), header.Version)
	require.Equal(t, proxyproto.TCPv4, header.TransportProtocol)
	require.Equal(t, "192.0.2.33:4444", header.SourceAddr.String())
	require.Equal(t, "198.51.100.1:80", header.DestinationAddr.String())

	ctx6 := adapter.WithContext(context.Background(), &adapter.InboundContext{
		Source: M.SocksaddrFrom(netip.MustParseAddr("2001:db8::33"), 4444),
	})
	header, err = hDialAndReadHeader(t, ctx6, M.SocksaddrFrom(netip.MustParseAddr("2001:db8::1"), 443))
	require.NoError(t, err)
	require.Equal(t, proxyproto.TCPv6, header.TransportProtocol)
	require.Equal(t, "[2001:db8::33]:4444", header.SourceAddr.String())
}

// a client of another address family than the destination cannot be described: without a usable
// local address the header is "unknown" (LOCAL), which receivers accept
func TestH_DialerMixedFamilies(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ source, destination string }{
		{"192.0.2.33", "2001:db8::1"},
		{"2001:db8::33", "192.0.2.1"},
	} {
		ctx := adapter.WithContext(context.Background(), &adapter.InboundContext{
			Source: M.SocksaddrFrom(netip.MustParseAddr(c.source), 4444),
		})
		header, err := hDialAndReadHeader(t, ctx, M.SocksaddrFrom(netip.MustParseAddr(c.destination), 443))
		require.NoError(t, err, "%s -> %s", c.source, c.destination)
		require.Equal(t, proxyproto.LOCAL, header.Command)
		require.Equal(t, proxyproto.UNSPEC, header.TransportProtocol)
	}
}

func TestH_DialerVersion2(t *testing.T) {
	t.Parallel()
	local, remote := net.Pipe()
	t.Cleanup(func() { local.Close(); remote.Close() })
	_ = remote.SetDeadline(time.Now().Add(2 * time.Second))
	headerCh := make(chan *proxyproto.Header, 1)
	go func() {
		header, _ := proxyproto.Read(bufio.NewReader(remote))
		headerCh <- header
	}()
	ctx := adapter.WithContext(context.Background(), &adapter.InboundContext{
		Source: M.SocksaddrFrom(netip.MustParseAddr("192.0.2.33"), 4444),
	})
	_, err := (&Dialer{Dialer: &hPipeDialer{conn: local}, Version: 2}).DialContext(ctx, N.NetworkTCP, M.SocksaddrFrom(netip.MustParseAddr("198.51.100.1"), 80))
	require.NoError(t, err)
	header := <-headerCh
	require.NotNil(t, header)
	require.Equal(t, byte(2), header.Version)
	require.Equal(t, "192.0.2.33:4444", header.SourceAddr.String())
}

func TestH_DialerFallsBackToLocalAddr(t *testing.T) {
	t.Parallel()
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer tcpListener.Close()
	headerCh := make(chan *proxyproto.Header, 1)
	go func() {
		conn, acceptErr := tcpListener.Accept()
		if acceptErr != nil {
			headerCh <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		header, _ := proxyproto.Read(bufio.NewReader(conn))
		headerCh <- header
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", tcpListener.Addr().String())
	require.NoError(t, err)
	defer raw.Close()
	dialer := &Dialer{Dialer: &hPipeDialer{conn: raw}}
	destination := M.SocksaddrFromNet(tcpListener.Addr())
	_, err = dialer.DialContext(ctx, N.NetworkTCP, destination)
	require.NoError(t, err)
	select {
	case header := <-headerCh:
		require.NotNil(t, header)
		require.Equal(t, raw.LocalAddr().String(), header.SourceAddr.String())
		require.Equal(t, tcpListener.Addr().String(), header.DestinationAddr.String())
	case <-time.After(3 * time.Second):
		t.Fatal("header not received")
	}
}

func TestH_DialerPassthrough(t *testing.T) {
	t.Parallel()
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	inner := &hPipeDialer{conn: local}
	dialer := &Dialer{Dialer: inner}
	destination := M.SocksaddrFrom(netip.MustParseAddr("192.0.2.1"), 53)
	conn, err := dialer.DialContext(context.Background(), N.NetworkUDP, destination)
	require.NoError(t, err)
	require.Equal(t, local, conn)
	require.Equal(t, N.NetworkUDP, inner.network)

	failing := &Dialer{Dialer: &hPipeDialer{err: io.ErrUnexpectedEOF}}
	_, err = failing.DialContext(context.Background(), N.NetworkTCP, destination)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestH_DialerWriteFailureClosesConn(t *testing.T) {
	t.Parallel()
	local, remote := net.Pipe()
	remote.Close()
	dialer := &Dialer{Dialer: &hPipeDialer{conn: local}}
	_, err := dialer.DialContext(context.Background(), N.NetworkTCP, M.SocksaddrFrom(netip.MustParseAddr("192.0.2.1"), 80))
	require.ErrorContains(t, err, "write proxy protocol header")
	_, err = local.Write([]byte{0})
	require.ErrorIs(t, err, io.ErrClosedPipe)
}

func TestH_DialerListenerRoundTrip(t *testing.T) {
	t.Parallel()
	listener, address := hListen(t, false)
	acceptCh := make(chan hAcceptResult, 1)
	go func() {
		conn, err := listener.Accept()
		acceptCh <- hAcceptResult{conn, err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	require.NoError(t, err)
	defer raw.Close()
	metadataCtx := adapter.WithContext(ctx, &adapter.InboundContext{
		Source: M.SocksaddrFrom(netip.MustParseAddr("203.0.113.9"), 5555),
	})
	dialer := &Dialer{Dialer: &hPipeDialer{conn: raw}}
	destination := M.SocksaddrFrom(netip.MustParseAddr("198.51.100.77"), 8443)
	conn, err := dialer.DialContext(metadataCtx, N.NetworkTCP, destination)
	require.NoError(t, err)
	_, err = conn.Write([]byte("payload"))
	require.NoError(t, err)
	select {
	case result := <-acceptCh:
		require.NoError(t, result.err)
		defer result.conn.Close()
		_ = result.conn.SetDeadline(time.Now().Add(2 * time.Second))
		require.Equal(t, "203.0.113.9:5555", result.conn.RemoteAddr().String())
		require.Equal(t, "198.51.100.77:8443", result.conn.LocalAddr().String())
		buffer := make([]byte, 7)
		_, err = io.ReadFull(result.conn, buffer)
		require.NoError(t, err)
		require.True(t, bytes.Equal([]byte("payload"), buffer))
	case <-time.After(3 * time.Second):
		t.Fatal("accept timeout")
	}
}

// a client that never sends its header is closed after the timeout and does not block others
func TestH_ListenerSilentClientDoesNotBlock(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	listener := newListener(tcpListener, false, 500*time.Millisecond)
	t.Cleanup(func() { listener.Close() })
	address := tcpListener.Addr().String()

	silent, err := net.DialTimeout("tcp", address, 2*time.Second)
	require.NoError(t, err)
	defer silent.Close()
	time.Sleep(50 * time.Millisecond) // the silent connection is accepted first

	header := proxyproto.HeaderProxyFromAddrs(1,
		&net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 1000},
		&net.TCPAddr{IP: net.IPv4(198, 51, 100, 20), Port: 443})
	start := time.Now()
	result := hAcceptWith(t, listener, address, append(hHeaderBytes(t, header), 'x'))
	require.NoError(t, result.err)
	require.Less(t, time.Since(start), 400*time.Millisecond, "accepting waited for the silent client")
	require.Equal(t, "192.0.2.10:1000", result.conn.RemoteAddr().String())

	_ = silent.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = silent.Read(make([]byte, 1))
	require.Error(t, err)
	require.False(t, errors.Is(err, os.ErrDeadlineExceeded), "the silent client was not closed after the header timeout")
}

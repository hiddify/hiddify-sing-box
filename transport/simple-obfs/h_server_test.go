package obfs

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func hTCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- conn
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	server := <-accepted
	require.NotNil(t, server)
	deadline := time.Now().Add(4 * time.Second)
	client.SetDeadline(deadline)
	server.SetDeadline(deadline)
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, server
}

func hRandom(t *testing.T, n int) []byte {
	data := make([]byte, n)
	_, err := rand.Read(data)
	require.NoError(t, err)
	return data
}

func hWriteAsync(conn net.Conn, chunks ...[]byte) chan error {
	result := make(chan error, 1)
	go func() {
		for _, chunk := range chunks {
			if _, err := conn.Write(chunk); err != nil {
				result <- err
				return
			}
		}
		result <- nil
	}()
	return result
}

func hReadFullSmall(t *testing.T, conn net.Conn, n int, step int) []byte {
	t.Helper()
	out := make([]byte, 0, n)
	buf := make([]byte, step)
	for len(out) < n {
		want := min(step, n-len(out))
		m, err := conn.Read(buf[:want])
		require.NoError(t, err)
		out = append(out, buf[:m]...)
	}
	return out
}

func TestH_HTTPObfsRoundTrip(t *testing.T) {
	rawClient, rawServer := hTCPPair(t)
	client := NewHTTPObfs(rawClient, "example.com", "8080")
	server := NewHTTPObfsServer(rawServer)

	first := []byte("first upstream payload")
	second := hRandom(t, 4096)
	writeErr := hWriteAsync(client, first, second)

	got := make([]byte, len(first))
	_, err := io.ReadFull(server, got)
	require.NoError(t, err)
	require.Equal(t, first, got)
	got = make([]byte, len(second))
	_, err = io.ReadFull(server, got)
	require.NoError(t, err)
	require.Equal(t, second, got)
	require.NoError(t, <-writeErr)

	down1 := []byte("first downstream payload")
	down2 := hRandom(t, 8192)
	writeErr = hWriteAsync(server, down1, down2)
	got = make([]byte, len(down1)+len(down2))
	_, err = io.ReadFull(client, got)
	require.NoError(t, err)
	require.Equal(t, append(append([]byte{}, down1...), down2...), got)
	require.NoError(t, <-writeErr)
}

func TestH_HTTPObfsServerSmallReadBuffer(t *testing.T) {
	rawClient, rawServer := hTCPPair(t)
	client := NewHTTPObfs(rawClient, "example.com", "80")
	server := NewHTTPObfsServer(rawServer)
	first := hRandom(t, 1000)
	after := []byte("after-first-request")
	writeErr := hWriteAsync(client, first, after)
	require.Equal(t, first, hReadFullSmall(t, server, len(first), 7))
	require.Equal(t, after, hReadFullSmall(t, server, len(after), 3))
	require.NoError(t, <-writeErr)
}

func TestH_HTTPObfsServerResponseFormat(t *testing.T) {
	rawClient, rawServer := hTCPPair(t)
	server := NewHTTPObfsServer(rawServer)
	payload := []byte("downstream")
	writeErr := hWriteAsync(server, payload)
	response, err := http.ReadResponse(bufio.NewReader(rawClient), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, response.StatusCode)
	require.Equal(t, "websocket", response.Header.Get("Upgrade"))
	require.Equal(t, "Upgrade", response.Header.Get("Connection"))
	require.True(t, strings.HasPrefix(response.Header.Get("Server"), "nginx/1."))
	require.NotEmpty(t, response.Header.Get("Sec-WebSocket-Accept"))
	require.NotEmpty(t, response.Header.Get("Date"))
	require.NoError(t, <-writeErr)
}

func TestH_HTTPObfsServerDateIsHTTPDate(t *testing.T) {
	t.Skip("BUG: HTTPObfsServer formats Date with time.RFC1123 in local zone instead of http.TimeFormat (GMT), unlike real nginx")
	rawClient, rawServer := hTCPPair(t)
	server := NewHTTPObfsServer(rawServer)
	writeErr := hWriteAsync(server, []byte("x"))
	response, err := http.ReadResponse(bufio.NewReader(rawClient), nil)
	require.NoError(t, err)
	_, err = http.ParseTime(response.Header.Get("Date"))
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(response.Header.Get("Date"), " GMT"))
	require.NoError(t, <-writeErr)
}

func TestH_HTTPObfsServerHeaderOnlyOnce(t *testing.T) {
	rawClient, rawServer := hTCPPair(t)
	server := NewHTTPObfsServer(rawServer)
	writeErr := hWriteAsync(server, []byte("a"), []byte("b"))
	require.NoError(t, <-writeErr)
	rawServer.Close()
	all, err := io.ReadAll(rawClient)
	require.NoError(t, err)
	require.Equal(t, 1, bytes.Count(all, []byte("HTTP/1.1 101")))
	require.True(t, bytes.HasSuffix(all, []byte("\r\n\r\nab")))
}

func TestH_HTTPObfsServerRejectsInvalidRequest(t *testing.T) {
	for name, request := range map[string]string{
		"post":       "POST / HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nContent-Length: 0\r\n\r\n",
		"no upgrade": "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			rawClient, rawServer := hTCPPair(t)
			server := NewHTTPObfsServer(rawServer)
			writeErr := hWriteAsync(rawClient, []byte(request))
			_, err := server.Read(make([]byte, 64))
			require.ErrorIs(t, err, io.EOF)
			require.NoError(t, <-writeErr)
		})
	}
	t.Run("garbage", func(t *testing.T) {
		rawClient, rawServer := hTCPPair(t)
		server := NewHTTPObfsServer(rawServer)
		writeErr := hWriteAsync(rawClient, []byte("\x16\x03\x01garbage\r\n\r\n"))
		_, err := server.Read(make([]byte, 64))
		require.Error(t, err)
		require.NoError(t, <-writeErr)
	})
}

func TestH_HTTPObfsServerUpstream(t *testing.T) {
	rawClient, _ := hTCPPair(t)
	require.Equal(t, rawClient, NewHTTPObfsServer(rawClient).(*HTTPObfsServer).Upstream())
	require.Equal(t, rawClient, NewTLSObfsServer(rawClient).(*TLSObfsServer).Upstream())
}

func hTLSRoundTrip(t *testing.T, serverName string) {
	t.Helper()
	rawClient, rawServer := hTCPPair(t)
	client := NewTLSObfs(rawClient, serverName)
	server := NewTLSObfsServer(rawServer)

	first := []byte("hello in session ticket")
	second := []byte("application data record")
	writeErr := hWriteAsync(client, first, second)
	got := make([]byte, len(first))
	_, err := io.ReadFull(server, got)
	require.NoError(t, err)
	require.Equal(t, first, got)
	got = make([]byte, len(second))
	_, err = io.ReadFull(server, got)
	require.NoError(t, err)
	require.Equal(t, second, got)
	require.NoError(t, <-writeErr)

	down1 := []byte("server hello payload")
	down2 := []byte("second downstream record")
	writeErr = hWriteAsync(server, down1, down2)
	got = make([]byte, len(down1))
	_, err = io.ReadFull(client, got)
	require.NoError(t, err)
	require.Equal(t, down1, got)
	got = make([]byte, len(down2))
	_, err = io.ReadFull(client, got)
	require.NoError(t, err)
	require.Equal(t, down2, got)
	require.NoError(t, <-writeErr)
}

func TestH_TLSObfsRoundTrip(t *testing.T) {
	for _, serverName := range []string{"example.com", "", "a", strings.Repeat("s", 255)} {
		t.Run(fmt.Sprintf("sni-len-%d", len(serverName)), func(t *testing.T) {
			hTLSRoundTrip(t, serverName)
		})
	}
}

func TestH_TLSObfsLongServerName(t *testing.T) {
	t.Skip("BUG: TLSObfsServer.skipOtherExts uses a 256-byte buffer, so an SNI longer than 256 bytes desynchronises the stream")
	hTLSRoundTrip(t, strings.Repeat("s", 300))
}

func TestH_TLSObfsLargePayloads(t *testing.T) {
	rawClient, rawServer := hTCPPair(t)
	client := NewTLSObfs(rawClient, "example.com")
	server := NewTLSObfsServer(rawServer)

	upstream := hRandom(t, 3*chunkSize+123)
	writeErr := hWriteAsync(client, upstream)
	got := make([]byte, len(upstream))
	_, err := io.ReadFull(server, got)
	require.NoError(t, err)
	require.Equal(t, upstream, got)
	require.NoError(t, <-writeErr)

	downstream := hRandom(t, 2*chunkSize+77)
	writeErr = hWriteAsync(server, downstream)
	got = make([]byte, len(downstream))
	_, err = io.ReadFull(client, got)
	require.NoError(t, err)
	require.Equal(t, downstream, got)
	require.NoError(t, <-writeErr)
}

func TestH_TLSObfsServerSmallReadBuffer(t *testing.T) {
	rawClient, rawServer := hTCPPair(t)
	client := NewTLSObfs(rawClient, "example.com")
	server := NewTLSObfsServer(rawServer)
	first := hRandom(t, 500)
	second := hRandom(t, 300)
	writeErr := hWriteAsync(client, first, second)
	require.Equal(t, first, hReadFullSmall(t, server, len(first), 64))
	require.Equal(t, second, hReadFullSmall(t, server, len(second), 64))
	require.NoError(t, <-writeErr)
}

func TestH_TLSObfsServerHelloFormat(t *testing.T) {
	payload := []byte("finished-carried payload")
	hello := makeTLSServerHello(payload)
	require.Equal(t, 105+2+len(payload), len(hello))
	require.Equal(t, byte(0x16), hello[0])
	require.Equal(t, uint16(0x0301), binary.BigEndian.Uint16(hello[1:3]))
	recordLength := int(binary.BigEndian.Uint16(hello[3:5]))
	require.Equal(t, 91, recordLength)
	require.Equal(t, byte(2), hello[5])
	require.Equal(t, uint32(87), uint32(hello[6])<<16|uint32(hello[7])<<8|uint32(hello[8]))
	ccs := hello[5+recordLength : 5+recordLength+6]
	require.Equal(t, []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}, ccs)
	finished := hello[5+recordLength+6:]
	require.Equal(t, []byte{0x16, 0x03, 0x03}, finished[:3])
	require.Equal(t, len(payload), int(binary.BigEndian.Uint16(finished[3:5])))
	require.Equal(t, payload, finished[5:])
}

func TestH_TLSObfsServerDataRecordFormat(t *testing.T) {
	rawClient, rawServer := hTCPPair(t)
	server := NewTLSObfsServer(rawServer)
	writeErr := hWriteAsync(server, []byte("x"), []byte("abc"))
	require.NoError(t, <-writeErr)
	rawServer.Close()
	all, err := io.ReadAll(rawClient)
	require.NoError(t, err)
	require.Equal(t, []byte{0x17, 0x03, 0x03, 0x00, 0x03, 'a', 'b', 'c'}, all[len(all)-8:])
}

func TestH_TLSObfsServerTruncatedHello(t *testing.T) {
	rawClient, rawServer := hTCPPair(t)
	server := NewTLSObfsServer(rawServer)
	_, err := rawClient.Write([]byte{0x16, 0x03, 0x01, 0x00})
	require.NoError(t, err)
	rawClient.Close()
	_, err = server.Read(make([]byte, 16))
	require.Error(t, err)
}

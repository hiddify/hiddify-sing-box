package obfs

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// hRealClientHello returns the first TLS record a real crypto/tls client sends.
func hRealClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	rawClient, rawServer := hTCPPair(t)
	go tls.Client(rawClient, &tls.Config{ServerName: serverName}).Handshake()
	header := make([]byte, 5)
	_, err := io.ReadFull(rawServer, header)
	require.NoError(t, err)
	record := make([]byte, 5+int(binary.BigEndian.Uint16(header[3:5])))
	copy(record, header)
	_, err = io.ReadFull(rawServer, record[5:])
	require.NoError(t, err)
	return record
}

func TestH_ServerHandshakeAcceptsObfs(t *testing.T) {
	for _, mode := range []string{"http", "tls"} {
		t.Run(mode, func(t *testing.T) {
			rawClient, rawServer := hTCPPair(t)
			var client net.Conn
			if mode == "http" {
				client = NewHTTPObfs(rawClient, "www.example.com", "443")
			} else {
				client = NewTLSObfs(rawClient, "www.example.com")
			}
			first := hRandom(t, 700)
			second := hRandom(t, 3*chunkSize+5)
			writeErr := hWriteAsync(client, first, second)
			server, cached, err := ServerHandshake(rawServer, mode)
			require.NoError(t, err)
			require.Nil(t, cached)
			got := make([]byte, len(first)+len(second))
			_, err = io.ReadFull(server, got)
			require.NoError(t, err)
			require.Equal(t, append(append([]byte{}, first...), second...), got)
			require.NoError(t, <-writeErr)

			down := hRandom(t, 2048)
			writeErr = hWriteAsync(server, down)
			got = make([]byte, len(down))
			_, err = io.ReadFull(client, got)
			require.NoError(t, err)
			require.Equal(t, down, got)
			require.NoError(t, <-writeErr)
		})
	}
}

// A request that is not simple-obfs must come back byte for byte, including
// whatever bufio read ahead, so the fallback server sees the original stream.
func TestH_ServerHandshakeReturnsProbeBytes(t *testing.T) {
	realHello := hRealClientHello(t, "www.example.com")
	plainGet := []byte("GET / HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: probe\r\n\r\n")
	websocketPost := []byte("POST / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nContent-Length: 0\r\n\r\n")
	cases := []struct {
		name  string
		mode  string
		probe []byte
	}{
		{"tls/real client hello", "tls", realHello},
		{"tls/plain http", "tls", plainGet},
		{"tls/garbage", "tls", hRandom(t, 300)},
		{"tls/handshake record too short", "tls", []byte{0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x00, 0x00, 0x0c, 0x03, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"http/real client hello", "http", realHello},
		{"http/plain get", "http", plainGet},
		{"http/post upgrade", "http", websocketPost},
		{"http/garbage", "http", append([]byte{0x00}, hRandom(t, 300)...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rawClient, rawServer := hTCPPair(t)
			// Trailing bytes model a client that keeps sending; only what was
			// read must be returned, and the rest must still be on the conn.
			trailer := []byte("trailing bytes")
			writeErr := hWriteAsync(rawClient, tc.probe, trailer)
			require.NoError(t, <-writeErr)
			server, cached, err := ServerHandshake(rawServer, tc.mode)
			require.ErrorIs(t, err, ErrNotObfs)
			require.Nil(t, server)
			require.NotEmpty(t, cached)
			rawClient.Close()
			rest, err := io.ReadAll(rawServer)
			require.NoError(t, err)
			sent := append(append([]byte{}, tc.probe...), trailer...)
			require.Equal(t, sent, append(cached, rest...))
		})
	}
}

func TestH_ServerHandshakeRejectsTamperedObfsHello(t *testing.T) {
	rawClient, rawServer := hTCPPair(t)
	go NewTLSObfs(rawClient, "www.example.com").Write([]byte("payload"))
	header := make([]byte, 5)
	_, err := io.ReadFull(rawServer, header)
	require.NoError(t, err)
	hello := make([]byte, binary.BigEndian.Uint16(header[3:5]))
	_, err = io.ReadFull(rawServer, hello)
	require.NoError(t, err)
	payload, _, err := parseTLSObfsClientHello(hello)
	require.NoError(t, err)
	require.Equal(t, []byte("payload"), payload)

	for name, offset := range map[string]int{
		"handshake type":        0,
		"session id length":     38,
		"cipher suites length":  72,
		"compression":           129,
		"extensions length":     132,
		"session ticket type":   134,
		"server name list size": tlsHelloFixedLength + 4 + len("payload") + 5,
	} {
		tampered := append([]byte{}, hello...)
		tampered[offset] ^= 0xff
		_, _, err := parseTLSObfsClientHello(tampered)
		require.ErrorIs(t, err, ErrNotObfs, name)
	}
}

func TestH_ServerHandshakeClosedBeforeRequest(t *testing.T) {
	for _, mode := range []string{"http", "tls"} {
		rawClient, rawServer := hTCPPair(t)
		rawClient.Write([]byte{0x16})
		rawClient.Close()
		_, cached, err := ServerHandshake(rawServer, mode)
		require.Error(t, err, mode)
		require.NotErrorIs(t, err, ErrNotObfs, mode)
		require.Equal(t, []byte{0x16}, cached, mode)
	}
}

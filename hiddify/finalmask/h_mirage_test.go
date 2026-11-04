package finalmask

import (
	"crypto/tls"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// clientHelloRecord is the first TLS record a Go client writes for serverName.
func clientHelloRecord(t *testing.T, serverName string) []byte {
	client, server := net.Pipe()
	defer server.Close()
	go func() { _ = tls.Client(client, &tls.Config{ServerName: serverName}).Handshake() }()
	defer client.Close()
	header := make([]byte, 5)
	_, err := io.ReadFull(server, header)
	require.NoError(t, err)
	record := make([]byte, 5+(int(header[3])<<8|int(header[4])))
	copy(record, header)
	_, err = io.ReadFull(server, record[5:])
	require.NoError(t, err)
	return record
}

// The mirage mask writes a ClientHello as two TLS records, each on its own, with the same
// handshake bytes; other writes pass through.
func TestH_FinalMaskMirage(t *testing.T) {
	hello := clientHelloRecord(t, "blocked.example.com")
	masks, err := Build(parseOptions(t, `{"tcp":[{"type":"mirage","settings":{"offset":4}}]}`))
	require.NoError(t, err)
	recorder := &writeRecorder{}
	conn, err := wrapTCP(masks, recorder)
	require.NoError(t, err)

	n, err := conn.Write(hello)
	require.NoError(t, err)
	require.Equal(t, len(hello), n)
	writes := recorder.recorded()
	require.Len(t, writes, 2)
	require.Equal(t, 5+4, len(writes[0]))
	require.Equal(t, byte(0x16), writes[0][0])
	require.Equal(t, byte(0x16), writes[1][0])
	require.Equal(t, hello[5:], append(append([]byte(nil), writes[0][5:]...), writes[1][5:]...))
	require.NotContains(t, string(writes[0]), "blocked.example.com")
	require.NotContains(t, string(writes[1][:5]), "blocked")

	_, err = conn.Write([]byte("later"))
	require.NoError(t, err)
	require.Len(t, recorder.recorded(), 3)
}

// layout "single" sends both records, and the bytes after them, in one write.
func TestH_FinalMaskMirageSingle(t *testing.T) {
	hello := clientHelloRecord(t, "blocked.example.com")
	masks, err := Build(parseOptions(t, `{"tcp":[{"type":"mirage","settings":{"offset":2,"layout":"single"}}]}`))
	require.NoError(t, err)
	recorder := &writeRecorder{}
	conn, err := wrapTCP(masks, recorder)
	require.NoError(t, err)

	n, err := conn.Write(append(append([]byte(nil), hello...), "tail"...))
	require.NoError(t, err)
	require.Equal(t, len(hello)+4, n)
	writes := recorder.recorded()
	require.Len(t, writes, 1)
	out := writes[0]
	require.Len(t, out, len(hello)+5+4)
	require.Equal(t, []byte{0x16, hello[1], hello[2], 0, 2}, out[:5])
	require.Equal(t, byte(0x16), out[7])
	require.Equal(t, hello[5:], append(append([]byte(nil), out[5:7]...), out[12:len(out)-4]...))
	require.Equal(t, "tail", string(out[len(out)-4:]))

	_, err = Build(parseOptions(t, `{"tcp":[{"type":"mirage","settings":{"layout":"both"}}]}`))
	require.Error(t, err)
}

// A first write that is not a complete ClientHello is sent unchanged.
func TestH_FinalMaskMirageNotClientHello(t *testing.T) {
	masks, err := Build(parseOptions(t, `{"tcp":[{"type":"mirage"}]}`))
	require.NoError(t, err)
	recorder := &writeRecorder{}
	conn, err := wrapTCP(masks, recorder)
	require.NoError(t, err)
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	require.NoError(t, err)
	require.Len(t, recorder.recorded(), 1)

	_, err = Build(parseOptions(t, `{"tcp":[{"type":"mirage","settings":{"offset":-1}}]}`))
	require.Error(t, err)
}

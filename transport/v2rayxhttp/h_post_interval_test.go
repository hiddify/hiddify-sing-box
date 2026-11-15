package xhttp

import (
	"context"
	"io"
	"testing"
	"time"

	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// hFirstEcho dials a packet-up connection, writes first and then, a moment later, second, and
// returns how long after second was written its echo came back.
func hFirstEcho(t *testing.T, first, second []byte) time.Duration {
	t.Helper()
	serverOptions := hOptions(t, `{"mode":"packet-up","path":"/xh","x_padding_bytes":"100-1000"}`)
	clientOptions := hOptions(t, `{"mode":"packet-up","path":"/xh","x_padding_bytes":"100-1000","sc_min_posts_interval_ms":"30"}`)
	addr := hStartServer(t, serverOptions, nil)
	transport, err := NewClient(context.Background(), N.SystemDialer, addr, clientOptions, nil)
	require.NoError(t, err)
	defer transport.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, err := transport.DialContext(ctx)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write(first)
	require.NoError(t, err)
	echo := make([]byte, len(first))
	_, err = io.ReadFull(conn, echo)
	require.NoError(t, err)
	time.Sleep(5 * time.Millisecond) // the application's first bytes come a moment after the request
	written := time.Now()
	_, err = conn.Write(second)
	require.NoError(t, err)
	echo = make([]byte, len(second))
	_, err = io.ReadFull(conn, echo)
	require.NoError(t, err)
	return time.Since(written)
}

// The application's first bytes go out at once after an upload that carried only the proxy
// protocol's request. VLESS, VMess and Trojan write their request as soon as the connection is
// up, and the application's first bytes, a TLS hello or an HTTP request, in a write of their own
// a moment later; held back by sc_min_posts_interval_ms after the request, they left 30 ms late
// on every new connection, and the first answer came 30 ms later than through Xray, which sends
// the request with the first bytes.
func TestH_PacketUpFirstBytesFollowTheRequestAtOnce(t *testing.T) {
	took := hFirstEcho(t, make([]byte, 40), []byte("GET / HTTP/1.1\r\n\r\n"))
	t.Logf("the first bytes came back %v after they were written", took)
	require.Less(t, took, 20*time.Millisecond, "the first bytes waited for the interval after the request")
}

// After an upload of data, the next one still waits sc_min_posts_interval_ms: only an upload that
// carried nothing but a request is followed at once.
func TestH_PacketUpKeepsTheIntervalAfterData(t *testing.T) {
	took := hFirstEcho(t, make([]byte, 4096), []byte("more"))
	t.Logf("the next bytes came back %v after they were written", took)
	require.Greater(t, took, 20*time.Millisecond, "an upload after data did not wait for the interval")
}

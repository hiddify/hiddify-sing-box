package xhttp

import (
	"context"
	"net"
	"net/http"
	"testing"

	Xbadoption "github.com/sagernet/sing-box/common/xray/json/badoption"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

type hFakeXmuxConn struct{ closed bool }

func (c *hFakeXmuxConn) IsClosed() bool { return c.closed }
func (c *hFakeXmuxConn) Close() error   { c.closed = true; return nil }

// A client is counted as running when it is picked: counted after, the next pick found it used up
// (c_max_reuse_times) with nothing on it and closed it before its caller used it.
func TestH_XmuxPickedClientIsNotClosedByTheNextPick(t *testing.T) {
	for _, reuse := range []int32{1, 2} {
		manager := NewXmuxManager(option.V2RayXHTTPXmuxOptions{
			MaxConcurrency: Xbadoption.Range{From: 1, To: 1},
			CMaxReuseTimes: Xbadoption.Range{From: reuse, To: reuse},
		}, func() XmuxConn { return &hFakeXmuxConn{} })
		for range 4 {
			first := manager.GetXmuxClient(context.Background())
			second := manager.GetXmuxClient(context.Background())
			require.False(t, first.XmuxConn.IsClosed(), "c_max_reuse_times %d: closed before it was used", reuse)
			first.DoneRunning()
			second.DoneRunning()
		}
	}
}

// With c_max_reuse_times 1 and no download block, a connection works: the download took a
// second pick, which closed the upload's client, and every connection failed.
func TestH_XmuxReuseOnceRoundTrip(t *testing.T) {
	options := `{"mode":"packet-up","path":"/xh","xmux":{"max_concurrency":"1","c_max_reuse_times":"1"}}`
	addr := hStartServer(t, hOptions(t, options), nil)
	for range 3 {
		hRoundTrip(t, hOptions(t, options), nil, addr, hPayloads(t, 1000, 2000)...)
	}
}

// A failed request marks a client as not to be used again; that is not Close: a connection the
// client dials after it (another stream on a shared client) is kept, and only Close closes them.
func TestH_FailedRequestDoesNotCloseLaterConnections(t *testing.T) {
	client := &DefaultDialerClient{client: &http.Client{}}
	client.closed.Store(true) // what a stream goroutine sets on a failed request
	local, remote := net.Pipe()
	defer remote.Close()
	tracked := client.hTrack(local)
	go remote.Read(make([]byte, 1))
	_, err := tracked.Write([]byte{1})
	require.NoError(t, err, "the connection was closed")
	require.True(t, client.IsClosed(), "the client is still not to be reused")

	require.NoError(t, client.Close())
	_, err = tracked.Write([]byte{1})
	require.Error(t, err, "Close closes it")
}

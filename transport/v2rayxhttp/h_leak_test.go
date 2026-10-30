package xhttp

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

// hHeaderReader reads the request header in NewConnectionEx, as the VLESS, Trojan and VMess
// inbounds do, before handing the connection on.
type hHeaderReader struct{}

func (hHeaderReader) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	header := make([]byte, 16)
	if _, err := io.ReadFull(conn, header); err != nil {
		conn.Close()
	}
}

// A client that opens the download (GET) and goes away before it uploads anything: the handler
// read the header from the upload queue forever, and the GET handler with its connection never
// ended (issue hiddify-core#163).
func TestH_XHTTPServerStreamDownClientGone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := NewServer(ctx, logger.NOP(), hOptions(t, `{"mode":"packet-up",`+hBase+`}`), nil, hHeaderReader{})
	require.NoError(t, err)
	requestCtx, requestCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer requestCancel()
	served := make(chan struct{})
	go func() {
		hServe(server, hRequest("GET", "/xh/gone/", nil, 150).WithContext(requestCtx))
		close(served)
	}()
	select {
	case <-served:
	case <-time.After(3 * time.Second):
		t.Fatal("the GET handler did not end after the client went away")
	}
}

// A full queue that nobody reads: Close waited for the mutex that a blocked Push held, forever.
func TestH_UploadQueueCloseWithBlockedPush(t *testing.T) {
	queue := NewUploadQueue(1)
	require.NoError(t, queue.Push(Packet{Payload: []byte("a"), Seq: 0}))
	pushed := make(chan error, 1)
	go func() { pushed <- queue.Push(Packet{Payload: []byte("b"), Seq: 1}) }()
	time.Sleep(50 * time.Millisecond) // the second Push waits for room
	closed := make(chan struct{})
	go func() {
		queue.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close waited for a blocked Push")
	}
	select {
	case err := <-pushed:
		require.Error(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("the blocked Push did not return after Close")
	}
}

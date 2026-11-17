package tunnel

import (
	"bytes"
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

// hRequestConn is a client's connection that has sent its request.
type hRequestConn struct {
	net.Conn
	request *bytes.Reader
}

func (c *hRequestConn) Read(p []byte) (int, error) { return c.request.Read(p) }
func (c *hRequestConn) Close() error               { return nil }

// A client's connections come in while dials take them from its queue, in any order: the server
// goes on. When the queue was full it took its oldest connection with a blocking receive; a dial
// that had emptied the queue a moment before left that receive waiting for good, with the
// server's lock held, and the whole server stood still.
func TestH_ServerQueueFullWhileDialsDrainIt(t *testing.T) {
	server := hNewServer(newHFakeRouter(), map[uuid.UUID]uuid.UUID{hUUIDB: hUUIDA})
	queue := make(chan net.Conn, 1) // full after one connection: every other one evicts
	server.conns[hUUIDA] = queue
	var request bytes.Buffer
	require.NoError(t, WriteRequest(&request, &Request{UUID: hUUIDB, Command: CommandInbound, Destination: Destination}))

	stop := make(chan struct{})
	defer close(stop)
	go func() { // the dials: they take what is in the queue
		for {
			select {
			case <-queue:
			case <-stop:
				return
			}
		}
	}()
	var handled atomic.Int64
	done := make(chan error, 1)
	go func() {
		for range 300000 {
			conn := &hRequestConn{request: bytes.NewReader(request.Bytes())}
			if err := server.connHandler(context.Background(), conn, adapter.InboundContext{Destination: Destination}, func(error) {}); err != nil {
				done <- err
				return
			}
			handled.Add(1)
		}
		done <- nil
	}()
	last, stalled := int64(-1), 0
	for {
		select {
		case err := <-done:
			require.NoError(t, err)
			return
		case <-time.After(500 * time.Millisecond):
		}
		if now := handled.Load(); now == last {
			if stalled++; stalled == 4 {
				t.Fatal("the server stands still after ", now, " connections: the queue's lock is held")
			}
		} else {
			last, stalled = now, 0
		}
	}
}

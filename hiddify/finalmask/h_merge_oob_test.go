package finalmask

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// writeRecorder records each Write that reaches it.
type writeRecorder struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (r *writeRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writes = append(r.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (r *writeRecorder) Close() error { return nil }

func (r *writeRecorder) recorded() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.writes...)
}

// The merge mask holds quick writes and sends them as one, times times; then writes pass through.
func TestH_FinalMaskMerge(t *testing.T) {
	masks, err := Build(parseOptions(t, `{"tcp":[{"type":"merge","settings":{"times":1,"delayMs":30,"maxBytes":16384}}]}`))
	require.NoError(t, err)
	recorder := &writeRecorder{}
	conn, err := wrapTCP(masks, recorder)
	require.NoError(t, err)

	conn.Write([]byte("hello "))
	conn.Write([]byte("world"))
	require.Empty(t, recorder.recorded(), "held until the idle time")
	require.Eventually(t, func() bool { return len(recorder.recorded()) == 1 }, time.Second, 5*time.Millisecond)
	require.Equal(t, "hello world", string(recorder.recorded()[0]))

	conn.Write([]byte("later"))
	require.Len(t, recorder.recorded(), 2, "the budget is spent: straight through")

	// maxBytes flushes at once; Close sends what is held
	masks, err = Build(parseOptions(t, `{"tcp":[{"type":"merge","settings":{"times":0,"maxBytes":4}}]}`))
	require.NoError(t, err)
	recorder = &writeRecorder{}
	conn, _ = wrapTCP(masks, recorder)
	conn.Write([]byte("abcdef"))
	require.Equal(t, [][]byte{[]byte("abcdef")}, recorder.recorded())
	conn.Write([]byte("x"))
	require.NoError(t, conn.Close())
	require.Equal(t, "x", string(recorder.recorded()[1]))

	_, err = Build(parseOptions(t, `{"tcp":[{"type":"merge","settings":{"delayMs":-1}}]}`))
	require.Error(t, err)
}

// The oob mask sends the first writes with an urgent byte; the server's TCP stack takes it out of
// the stream, so the server reads exactly what was written.
func TestH_FinalMaskOOB(t *testing.T) {
	masks, err := Build(parseOptions(t, `{"tcp":[{"type":"oob","settings":{"bytes":[0,65]}}]}`))
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	received := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn)
		received <- data
	}()

	raw, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	conn, err := wrapTCP(masks, raw)
	require.NoError(t, err)
	for _, part := range []string{"first ", "second ", "third"} {
		n, err := conn.Write([]byte(part))
		require.NoError(t, err)
		require.Equal(t, len(part), n, "the urgent byte is not counted")
		time.Sleep(20 * time.Millisecond) // separate segments
	}
	require.NoError(t, conn.Close())
	select {
	case data := <-received:
		require.Equal(t, "first second third", string(data))
	case <-time.After(3 * time.Second):
		t.Fatal("nothing received")
	}

	// a connection that is not a socket is left as it is
	recorder := &writeRecorder{}
	conn, _ = wrapTCP(masks, recorder)
	conn.Write([]byte("plain"))
	require.Equal(t, "plain", string(recorder.recorded()[0]))

	for _, settings := range []string{`{}`, `{"bytes":[]}`, `{"bytes":[256]}`, `{"bytes":[-1]}`} {
		_, err := Build(parseOptions(t, `{"tcp":[{"type":"oob","settings":`+settings+`}]}`))
		require.Error(t, err, settings)
	}
	_, err = Build(parseOptions(t, `{"udp":[{"type":"oob","settings":{"bytes":[0]}}]}`))
	require.Error(t, err, "oob is a tcp mask")
}

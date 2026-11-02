//go:build unix

package finalmask

import (
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// With SO_OOBINLINE the server keeps urgent bytes in the stream: they show the oob mask really
// sends each of the first writes with its byte as urgent data, not as a plain write.
func TestH_FinalMaskOOBSendsUrgentBytes(t *testing.T) {
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
		raw, _ := conn.(*net.TCPConn).SyscallConn()
		raw.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_OOBINLINE, 1)
		})
		data, _ := io.ReadAll(conn)
		received <- data
	}()
	raw, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	conn, err := wrapTCP(masks, raw)
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond) // the server sets SO_OOBINLINE before data arrives
	for _, part := range []string{"first ", "second ", "third"} {
		_, err := conn.Write([]byte(part))
		require.NoError(t, err)
		time.Sleep(20 * time.Millisecond)
	}
	require.NoError(t, conn.Close())
	require.Equal(t, "first \x00second Athird", string(<-received))
}

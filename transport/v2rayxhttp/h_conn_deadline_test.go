package xhttp

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing/common/bufio/deadline"

	"github.com/stretchr/testify/require"
)

// splitConn cannot set deadlines itself; it must say so, so that the router wraps it (as it does
// for gRPC and HTTP) and a read deadline, such as the sniff timeout, still ends the read.
func TestH_XHTTPSplitConnReadDeadline(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	var conn net.Conn = &splitConn{writer: writer, reader: reader}
	require.ErrorIs(t, conn.SetReadDeadline(time.Now()), os.ErrInvalid)
	if deadline.NeedAdditionalReadDeadline(conn) {
		conn = deadline.NewConn(conn)
	}
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
	result := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		result <- err
	}()
	select {
	case err := <-result:
		var netErr net.Error
		require.True(t, errors.As(err, &netErr) && netErr.Timeout(), "%v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("the read deadline was ignored")
	}
}

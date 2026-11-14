package v2raygrpc

import (
	"context"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// silentServer accepts connections and never says a word: a server that is down behind a port that
// still answers, or a middlebox that swallows the handshake.
func silentServer(t *testing.T) M.Socksaddr {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var conns []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conns = append(conns, conn)
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-done
		for _, conn := range conns {
			conn.Close()
		}
	})
	return M.SocksaddrFromNet(listener.Addr())
}

// grpcRoutines counts the goroutines of gRPC client connections.
func grpcRoutines() int {
	buf := make([]byte, 4<<20)
	stacks := string(buf[:runtime.Stack(buf, true)])
	return strings.Count(stacks, "google.golang.org/grpc.(*addrConn)") + strings.Count(stacks, "grpc.(*ClientConn).WaitForStateChange")
}

// A dial to a server that does not answer ends with the caller's context. It ran on the client's
// own, which never ends: the caller hung for good whatever its deadline, and gRPC kept redialing
// the server behind it.
func TestH_GRPCDialEndsWithItsContext(t *testing.T) {
	before := grpcRoutines()
	client, err := NewClient(context.Background(), N.SystemDialer, silentServer(t), option.V2RayGRPCOptions{ServiceName: "tun"}, nil)
	require.NoError(t, err)
	defer client.Close()

	for range 2 { // the second one finds no dial left over from the first
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		started := time.Now()
		_, err = client.DialContext(ctx)
		cancel()
		require.Error(t, err)
		require.Less(t, time.Since(started), 3*time.Second, "the dial outlived its context")
	}
	require.Eventually(t, func() bool { return grpcRoutines() <= before }, 5*time.Second, 20*time.Millisecond,
		"gRPC goes on redialing the server after the dial gave up")
}

// Closing the client ends a dial that is under way: the dial has no connection yet for Close to
// close, so it went on, and with it gRPC's redialing, after the outbound was gone.
func TestH_GRPCCloseEndsADialUnderWay(t *testing.T) {
	before := grpcRoutines()
	client, err := NewClient(context.Background(), N.SystemDialer, silentServer(t), option.V2RayGRPCOptions{ServiceName: "tun"}, nil)
	require.NoError(t, err)
	dialed := make(chan error, 1)
	go func() {
		_, err := client.DialContext(context.Background())
		dialed <- err
	}()
	time.Sleep(200 * time.Millisecond)
	require.NoError(t, client.Close())
	select {
	case err := <-dialed:
		require.Error(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("the dial went on after the client closed")
	}
	require.Eventually(t, func() bool { return grpcRoutines() <= before }, 5*time.Second, 20*time.Millisecond,
		"gRPC goes on redialing the server after the client closed")
}

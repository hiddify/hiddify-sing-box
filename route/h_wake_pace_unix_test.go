//go:build unix

package route

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The plain reads of a busy datagram socket go through the paced raw connection, and are still
// what a read of the socket is: every datagram, whole, in order, a deadline that ends the read,
// and the error of a closed socket.
func TestH_BusyDatagramSocketReads(t *testing.T) {
	if pacingDisabled {
		t.Skip("pacing is off")
	}
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer server.Close()
	client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	require.NoError(t, client.SetReadBuffer(4<<20))
	manager := &ConnectionManager{}
	tracked := manager.TrackConn(client).(*trackedConn)
	require.NotNil(t, tracked.raw)
	clientAddr := client.LocalAddr().(*net.UDPAddr)

	const count = 6000
	go func() {
		payload := make([]byte, 1200)
		for i := range count {
			binary.BigEndian.PutUint32(payload, uint32(i))
			size := 1200
			if i%7 == 0 {
				size = 40 // an acknowledgement among the data
			}
			server.WriteToUDP(payload[:size], clientAddr)
			if i%16 == 15 {
				time.Sleep(200 * time.Microsecond) // about 60000 datagrams a second, in bursts
			}
		}
	}()
	buffer := make([]byte, 2048)
	var usedRaw bool
	for i := range count {
		require.NoError(t, tracked.SetReadDeadline(time.Now().Add(5*time.Second)))
		n, err := tracked.Read(buffer)
		require.NoError(t, err)
		expected := 1200
		if i%7 == 0 {
			expected = 40
		}
		require.Equal(t, expected, n, "datagram %d", i)
		require.Equal(t, uint32(i), binary.BigEndian.Uint32(buffer), "datagrams arrive whole and in order")
		usedRaw = usedRaw || tracked.rate.busy
	}
	require.True(t, usedRaw, "a busy socket's reads went through the raw connection")
	require.True(t, tracked.wake.path.local.Load())
	require.Zero(t, tracked.wake.wait, "a socket whose peer is this machine is never held back")

	// make sure the next reads use the raw connection, whatever the rate was at the end
	tracked.rate.busy = true
	// a zero-length datagram is a read of nothing, not an end
	_, err = server.WriteToUDP(nil, clientAddr)
	require.NoError(t, err)
	n, err := tracked.Read(buffer)
	require.NoError(t, err)
	require.Zero(t, n)
	// a deadline ends a read that waits
	tracked.rate.busy = true
	require.NoError(t, tracked.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	started := time.Now()
	_, err = tracked.Read(buffer)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	var netErr net.Error
	require.True(t, errors.As(err, &netErr) && netErr.Timeout())
	require.Less(t, time.Since(started), time.Second)
	// closing the socket ends a read that waits
	tracked.rate.busy = true
	require.NoError(t, tracked.SetReadDeadline(time.Time{}))
	result := make(chan error, 1)
	go func() {
		_, err := tracked.Read(buffer)
		result <- err
	}()
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, tracked.Close())
	select {
	case err = <-result:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(3 * time.Second):
		t.Fatal("the read did not end when the socket was closed")
	}
}

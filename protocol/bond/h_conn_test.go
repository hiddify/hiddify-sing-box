//go:build with_bond

package bond

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// a write larger than one frame arrives whole: the frame length is a uint16
func TestH_BondedConnLargeWrite(t *testing.T) {
	var clientLegs, serverLegs []net.Conn
	for range 3 {
		client, server := net.Pipe()
		clientLegs = append(clientLegs, client)
		serverLegs = append(serverLegs, server)
	}
	ratios := []uint8{20, 30, 50}
	client := newBondedConn(clientLegs, ratios, ratios, nil)
	server := newBondedConn(serverLegs, ratios, ratios, nil)
	defer client.Close()
	defer server.Close()
	payload := make([]byte, 300_000)
	rand.Read(payload)
	go func() {
		n, err := client.Write(payload)
		if err != nil || n != len(payload) {
			client.Close()
		}
	}()
	received := make([]byte, len(payload))
	_, err := io.ReadFull(server, received)
	require.NoError(t, err)
	require.True(t, bytes.Equal(payload, received))
}

// ratios that wrap around in a uint8 to 100 are refused
func TestH_BondRatios(t *testing.T) {
	require.NoError(t, checkRatios("upload", []uint8{40, 60}))
	require.Error(t, checkRatios("upload", []uint8{200, 156}), "356 is not 100")
	require.Error(t, checkRatios("upload", []uint8{50}))
}

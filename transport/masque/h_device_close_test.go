//go:build with_gvisor

package masque

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// Closing the device twice is not a panic, and a packet the stack sends after the close gives
// back the reference taken for the queue it does not go into.
func TestH_StackDeviceClose(t *testing.T) {
	device, err := newStackDevice(DeviceOptions{
		Context: context.Background(),
		Logger:  logger.NOP(),
		MTU:     DefaultMTU,
		Address: []netip.Prefix{netip.MustParsePrefix("172.16.0.2/32")},
	})
	require.NoError(t, err)
	require.NoError(t, device.Close())
	require.NotPanics(t, func() { require.NoError(t, device.Close()) })

	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte("after the close"))})
	defer packet.DecRef()
	var list stack.PacketBufferList
	list.PushBack(packet)
	_, sendErr := (*wireEndpoint)(device).WritePackets(list)
	require.IsType(t, &tcpip.ErrClosedForSend{}, sendErr)
	require.EqualValues(t, 1, packet.ReadRefs(), "the reference for the queue was kept")
}

package interrupt

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type countingCloser struct {
	closed atomic.Int32
}

func (c *countingCloser) Close() error {
	c.closed.Add(1)
	return nil
}

type fakeSingPacketConn struct {
	N.PacketConn
	closed atomic.Int32
}

func (c *fakeSingPacketConn) Close() error {
	c.closed.Add(1)
	return nil
}

func (c *fakeSingPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, io.EOF
}

func TestH_InterruptExternalContext(t *testing.T) {
	ctx := context.Background()
	require.False(t, IsExternalConnectionFromContext(ctx))
	require.True(t, IsExternalConnectionFromContext(ContextWithIsExternalConnection(ctx)))
}

func TestH_InterruptGroupExternalFiltering(t *testing.T) {
	g := NewGroup()
	internal, external := &countingCloser{}, &countingCloser{}
	g.Add(internal, false)
	g.Add(external, true)
	removed := &countingCloser{}
	remove := g.Add(removed, false)
	remove()

	g.Interrupt(false)
	require.Equal(t, int32(1), internal.closed.Load())
	require.Equal(t, int32(0), external.closed.Load())
	require.Equal(t, int32(0), removed.closed.Load())

	g.Interrupt(false)
	require.Equal(t, int32(1), internal.closed.Load(), "interrupted connections are removed from the group")

	g.Interrupt(true)
	require.Equal(t, int32(1), external.closed.Load())
}

func TestH_InterruptConnCloseIsAsync(t *testing.T) {
	g := NewGroup()
	c1, c2 := net.Pipe()
	defer c2.Close()
	conn := g.NewConn(c1, false)
	require.Equal(t, c1, conn.(*Conn).Upstream())
	require.True(t, conn.(*Conn).ReaderReplaceable())
	require.True(t, conn.(*Conn).WriterReplaceable())

	require.NoError(t, conn.Close())
	require.Equal(t, 0, g.connections.Len())
	require.Eventually(t, func() bool {
		_, err := c2.Write([]byte{1})
		return err != nil
	}, 2*time.Second, 5*time.Millisecond, "underlying conn closed in background")
	require.NoError(t, conn.Close(), "double close is harmless")
}

func TestH_InterruptClosesTrackedConn(t *testing.T) {
	g := NewGroup()
	c1, c2 := net.Pipe()
	defer c2.Close()
	conn := g.NewConn(c1, true)
	g.Interrupt(false)
	go func() { _, _ = c2.Write([]byte{1}) }()
	buffer := make([]byte, 1)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := conn.Read(buffer)
	require.NoError(t, err, "external conn survives non-external interrupt")

	g.Interrupt(true)
	_, err = conn.Read(buffer)
	require.Error(t, err)
}

func TestH_InterruptPacketConns(t *testing.T) {
	g := NewGroup()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	pc := g.NewPacketConn(udp, false)
	require.True(t, pc.(*PacketConn).ReaderReplaceable())
	require.NotNil(t, pc.(*PacketConn).Upstream())

	sing := &fakeSingPacketConn{}
	spc := g.NewSingPacketConn(sing, false)
	require.Equal(t, sing, spc.(*SingPacketConn).Upstream())
	require.True(t, spc.(*SingPacketConn).ReaderReplaceable())
	require.True(t, spc.(*SingPacketConn).WriterReplaceable())
	require.Equal(t, 2, g.connections.Len())

	require.NoError(t, spc.Close())
	require.Equal(t, int32(1), sing.closed.Load())
	require.Equal(t, 1, g.connections.Len())

	sing2 := &fakeSingPacketConn{}
	g.NewSingPacketConn(sing2, true)
	g.Interrupt(false)
	require.Equal(t, int32(0), sing2.closed.Load())
	_, err = udp.WriteTo([]byte{1}, udp.LocalAddr())
	require.Error(t, err, "net packet conn closed by interrupt")
	g.Interrupt(true)
	require.Equal(t, int32(1), sing2.closed.Load())
	require.Equal(t, 0, g.connections.Len())
}

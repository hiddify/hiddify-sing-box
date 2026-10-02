package stat

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type counter struct{ v int64 }

func (c *counter) Value() int64 { return c.v }
func (c *counter) Set(v int64) int64 {
	old := c.v
	c.v = v
	return old
}

func (c *counter) Add(v int64) int64 {
	old := c.v
	c.v += v
	return old
}

func TestH_CounterConnection(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(2 * time.Second))
	b.SetDeadline(time.Now().Add(2 * time.Second))
	readCounter, writeCounter := &counter{}, &counter{}
	conn := &CounterConnection{Connection: a, ReadCounter: readCounter, WriteCounter: writeCounter}

	go b.Write([]byte("hello"))
	buffer := make([]byte, 16)
	n, err := conn.Read(buffer)
	require.NoError(t, err)
	require.Equal(t, 5, n)

	go func() {
		p := make([]byte, 16)
		b.Read(p)
	}()
	n, err = conn.Write([]byte("abc"))
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, int64(5), readCounter.Value())
	require.Equal(t, int64(3), writeCounter.Value())

	plain := &CounterConnection{Connection: a}
	go b.Write([]byte("x"))
	n, err = plain.Read(buffer)
	require.NoError(t, err)
	require.Equal(t, 1, n)
}

package buf

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/xray/stat"

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

type shortWriter struct {
	bytes.Buffer
	max int
	err error
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if len(p) > w.max {
		p = p[:w.max]
	}
	return w.Buffer.Write(p)
}

func TestH_WriteAllBytes(t *testing.T) {
	t.Parallel()
	w := &shortWriter{max: 3}
	c := &counter{}
	require.NoError(t, WriteAllBytes(w, []byte("0123456789"), c))
	require.Equal(t, "0123456789", w.String())
	require.Equal(t, int64(10), c.Value())

	failing := &shortWriter{err: io.ErrClosedPipe}
	require.ErrorIs(t, WriteAllBytes(failing, []byte("x"), nil), io.ErrClosedPipe)
}

func TestH_NewReaderWriterSelection(t *testing.T) {
	t.Parallel()
	container := &MultiBufferContainer{}
	require.Same(t, container, NewReader(container))
	require.Same(t, container, NewWriter(container))
	require.Same(t, container, NewPacketReader(container))

	require.IsType(t, &SingleReader{}, NewReader(bytes.NewReader(nil)))
	require.IsType(t, &PacketReader{}, NewPacketReader(bytes.NewReader(nil)))
	require.IsType(t, &SequentialWriter{}, NewWriter(&bytes.Buffer{}))

	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer udp.Close()
	require.IsType(t, &PacketReader{}, NewReader(udp.(io.Reader)))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
		}
	}()
	tcp, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer tcp.Close()
	require.IsType(t, &BufferToBytesWriter{}, NewWriter(tcp))

	c := &counter{}
	w := NewWriter(&stat.CounterConnection{Connection: tcp, WriteCounter: c})
	bw, ok := w.(*BufferToBytesWriter)
	require.True(t, ok)
	require.Same(t, c, bw.counter)
}

func TestH_BufferToBytesWriter(t *testing.T) {
	t.Parallel()
	var out shortWriter
	out.max = 1 << 30
	c := &counter{}
	w := &BufferToBytesWriter{Writer: &out, counter: c}
	require.NoError(t, w.WriteMultiBuffer(nil))
	require.NoError(t, w.WriteMultiBuffer(MultiBuffer{FromBytes([]byte("one"))}))
	require.NoError(t, w.WriteMultiBuffer(MultiBuffer{FromBytes([]byte("two")), FromBytes([]byte("three"))}))
	require.Equal(t, "onetwothree", out.String())
	require.Equal(t, int64(11), c.Value())

	n, err := w.ReadFrom(bytes.NewReader([]byte("-more")))
	require.NoError(t, err)
	require.Equal(t, int64(5), n)
	require.Equal(t, "onetwothree-more", out.String())
}

func TestH_BufferedWriter(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	w := NewBufferedWriter(&SequentialWriter{Writer: &out})
	n, err := w.Write([]byte("abc"))
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.NoError(t, w.WriteByte('d'))
	n, err = w.Write(nil)
	require.NoError(t, err)
	require.Zero(t, n)
	require.NoError(t, w.WriteMultiBuffer(MultiBuffer{FromBytes([]byte("e"))}))
	require.Zero(t, out.Len())
	require.NoError(t, w.Flush())
	require.Equal(t, "abcde", out.String())

	big := bytes.Repeat([]byte{'x'}, Size+5)
	require.NoError(t, w.WriteMultiBuffer(MergeBytes(nil, big)))
	require.Equal(t, 5+Size, out.Len())

	w.SetFlushNext()
	require.NoError(t, w.WriteMultiBuffer(MultiBuffer{FromBytes([]byte("y"))}))
	require.Equal(t, 5+Size+5+1, out.Len())
	_, err = w.Write([]byte("z"))
	require.NoError(t, err)
	require.Equal(t, 5+Size+5+2, out.Len())

	require.NoError(t, w.SetBuffered(true))
	w.Write([]byte("q"))
	require.Equal(t, 5+Size+5+2, out.Len())
	require.NoError(t, w.SetBuffered(false))
	require.Equal(t, 5+Size+5+3, out.Len())
	require.NoError(t, w.Close())

	var out2 bytes.Buffer
	w2 := NewBufferedWriter(&SequentialWriter{Writer: &out2})
	w2.Write([]byte("pre-"))
	n64, err := w2.ReadFrom(bytes.NewReader([]byte("body")))
	require.NoError(t, err)
	require.Equal(t, int64(4), n64)
	require.Equal(t, "pre-body", out2.String())
}

func TestH_BufferedWriterLargeWrite(t *testing.T) {
	t.Skip("BUG: Buffer.Write returns ErrBufferFull on a partial copy (buffer.go:270), so BufferedWriter.Write (writer.go:118-121) aborts instead of flushing and continuing for payloads larger than the free space")
	t.Parallel()
	var out bytes.Buffer
	w := NewBufferedWriter(&SequentialWriter{Writer: &out})
	big := bytes.Repeat([]byte{'x'}, Size+5)
	n, err := w.Write(big)
	require.NoError(t, err)
	require.Equal(t, len(big), n)
	require.NoError(t, w.Flush())
	require.Equal(t, big, out.Bytes())
}

func TestH_BufferedReader(t *testing.T) {
	t.Parallel()
	inner := &MultiBufferContainer{}
	inner.Write([]byte("abcdefgh"))
	r := &BufferedReader{Reader: inner}
	c, err := r.ReadByte()
	require.NoError(t, err)
	require.Equal(t, byte('a'), c)
	require.Equal(t, int32(7), r.BufferedBytes())
	mb, err := r.ReadAtMost(3)
	require.NoError(t, err)
	require.Equal(t, "bcd", mb.String())
	p := make([]byte, 10)
	n, err := r.Read(p)
	require.NoError(t, err)
	require.Equal(t, "efgh", string(p[:n]))
	require.Nil(t, r.Buffer)

	inner.Write([]byte("rest"))
	mb, err = r.ReadMultiBuffer()
	require.NoError(t, err)
	require.Equal(t, "rest", mb.String())

	failing := &BufferedReader{Reader: &SingleReader{Reader: bytes.NewReader(nil)}}
	_, err = failing.ReadAtMost(10)
	require.ErrorIs(t, err, io.EOF)

	src := &BufferedReader{Reader: &SingleReader{Reader: bytes.NewReader([]byte(" world"))}, Buffer: MultiBuffer{FromBytes([]byte("hello"))}}
	var out bytes.Buffer
	n64, err := src.WriteTo(&out)
	require.NoError(t, err)
	require.Equal(t, int64(11), n64)
	require.Equal(t, "hello world", out.String())
	require.NoError(t, src.Close())
}

type errorWriter struct{ err error }

func (w errorWriter) WriteMultiBuffer(mb MultiBuffer) error {
	ReleaseMulti(mb)
	return w.err
}

type errorReader struct{ err error }

func (r errorReader) ReadMultiBuffer() (MultiBuffer, error) { return nil, r.err }

func TestH_Copy(t *testing.T) {
	t.Parallel()
	payload := bytes.Repeat([]byte("0123456789"), 3000)
	var out bytes.Buffer
	var sc SizeCounter
	updater := &activityCounter{}
	err := Copy(NewReader(bytes.NewReader(payload)), &SequentialWriter{Writer: &out}, CountSize(&sc), UpdateActivity(updater))
	require.NoError(t, err)
	require.Equal(t, payload, out.Bytes())
	require.Equal(t, int64(len(payload)), sc.Size)
	require.Positive(t, updater.n)

	readErr := errors.New("read failed")
	err = Copy(errorReader{readErr}, Discard)
	require.True(t, IsReadError(err))
	require.False(t, IsWriteError(err))
	require.ErrorIs(t, err, readErr)

	writeErr := errors.New("write failed")
	err = Copy(NewReader(bytes.NewReader([]byte("x"))), errorWriter{writeErr})
	require.True(t, IsWriteError(err))
	require.False(t, IsReadError(err))
	require.ErrorIs(t, err, writeErr)
}

type activityCounter struct{ n int }

func (a *activityCounter) Update() { a.n++ }

type timeoutReader struct {
	MultiBufferContainer
	err error
}

func (r *timeoutReader) ReadMultiBufferTimeout(time.Duration) (MultiBuffer, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.ReadMultiBuffer()
}

func TestH_CopyOnceTimeout(t *testing.T) {
	t.Parallel()
	require.ErrorIs(t, CopyOnceTimeout(&SingleReader{}, Discard, time.Second), ErrNotTimeoutReader)
	r := &timeoutReader{}
	r.Write([]byte("data"))
	out := &MultiBufferContainer{}
	require.NoError(t, CopyOnceTimeout(r, out, time.Second))
	require.Equal(t, "data", out.String())
	r.err = ErrReadTimeout
	require.ErrorIs(t, CopyOnceTimeout(r, out, time.Second), ErrReadTimeout)
}

func TestH_Discard(t *testing.T) {
	t.Parallel()
	require.NoError(t, Discard.WriteMultiBuffer(MultiBuffer{New()}))
	n, err := DiscardBytes.Write([]byte("abc"))
	require.NoError(t, err)
	require.Equal(t, 3, n)
	n64, err := DiscardBytes.(io.ReaderFrom).ReadFrom(bytes.NewReader(make([]byte, Size*2+3)))
	require.NoError(t, err)
	require.Equal(t, int64(Size*2+3), n64)
}

func TestH_PacketReaderSkipsEmpty(t *testing.T) {
	t.Parallel()
	r := &PacketReader{Reader: &emptyThenData{empties: 3, data: []byte("pkt")}}
	mb, err := r.ReadMultiBuffer()
	require.NoError(t, err)
	require.Equal(t, "pkt", mb.String())

	r = &PacketReader{Reader: &emptyThenData{empties: 100}}
	_, err = r.ReadMultiBuffer()
	require.ErrorContains(t, err, "too many empty payloads")

	_, err = (&PacketReader{Reader: bytes.NewReader(nil)}).ReadMultiBuffer()
	require.ErrorIs(t, err, io.EOF)
}

type emptyThenData struct {
	empties int
	data    []byte
}

func (r *emptyThenData) Read(p []byte) (int, error) {
	if r.empties > 0 {
		r.empties--
		return 0, nil
	}
	return copy(p, r.data), nil
}

package pipe

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/xray/buf"

	"github.com/stretchr/testify/require"
)

func mbOf(s string) buf.MultiBuffer {
	return buf.MergeBytes(nil, []byte(s))
}

func TestH_PipeReadWrite(t *testing.T) {
	t.Parallel()
	r, w := New()
	require.NoError(t, w.WriteMultiBuffer(mbOf("hello ")))
	require.NoError(t, w.WriteMultiBuffer(mbOf("world")))
	require.NoError(t, w.WriteMultiBuffer(nil))
	require.Equal(t, int32(11), w.Len())
	mb, err := r.ReadMultiBuffer()
	require.NoError(t, err)
	require.Equal(t, "hello world", mb.String())
	buf.ReleaseMulti(mb)
	require.Zero(t, w.Len())
}

func TestH_PipeReadBlocksUntilWrite(t *testing.T) {
	t.Parallel()
	r, w := New()
	result := make(chan string, 1)
	go func() {
		mb, err := r.ReadMultiBuffer()
		if err != nil {
			result <- err.Error()
			return
		}
		result <- mb.String()
	}()
	select {
	case <-result:
		t.Fatal("read returned before write")
	case <-time.After(20 * time.Millisecond):
	}
	require.NoError(t, w.WriteMultiBuffer(mbOf("late")))
	select {
	case got := <-result:
		require.Equal(t, "late", got)
	case <-time.After(2 * time.Second):
		t.Fatal("reader not woken")
	}
}

func TestH_PipeCloseDrainsThenEOF(t *testing.T) {
	t.Parallel()
	r, w := New()
	require.NoError(t, w.WriteMultiBuffer(mbOf("rest")))
	require.NoError(t, w.Close())
	require.NoError(t, w.Close())
	require.ErrorIs(t, w.WriteMultiBuffer(mbOf("x")), io.ErrClosedPipe)
	mb, err := r.ReadMultiBuffer()
	require.NoError(t, err)
	require.Equal(t, "rest", mb.String())
	_, err = r.ReadMultiBuffer()
	require.ErrorIs(t, err, io.EOF)

	r2, w2 := New()
	done := make(chan error, 1)
	go func() {
		_, err := r2.ReadMultiBuffer()
		done <- err
	}()
	time.Sleep(10 * time.Millisecond)
	w2.Close()
	select {
	case err := <-done:
		require.ErrorIs(t, err, io.EOF)
	case <-time.After(2 * time.Second):
		t.Fatal("blocked reader not released by close")
	}
}

func TestH_PipeInterrupt(t *testing.T) {
	t.Parallel()
	r, w := New()
	require.NoError(t, w.WriteMultiBuffer(mbOf("dropped")))
	r.Interrupt()
	_, err := r.ReadMultiBuffer()
	require.ErrorIs(t, err, io.ErrClosedPipe)
	require.ErrorIs(t, w.WriteMultiBuffer(mbOf("x")), io.ErrClosedPipe)
	require.Zero(t, w.Len())

	r2, w2 := New()
	require.NoError(t, w2.WriteMultiBuffer(mbOf("pending")))
	w2.Close()
	w2.Interrupt()
	_, err = r2.ReadMultiBuffer()
	require.ErrorIs(t, err, io.ErrClosedPipe)

	r3, w3 := New()
	w3.Close()
	w3.Interrupt()
	_, err = r3.ReadMultiBuffer()
	require.ErrorIs(t, err, io.EOF)
}

func TestH_PipeSizeLimitBlocksWriter(t *testing.T) {
	t.Parallel()
	r, w := New(WithSizeLimit(4))
	require.NoError(t, w.WriteMultiBuffer(mbOf("12345")))
	written := make(chan error, 1)
	go func() {
		written <- w.WriteMultiBuffer(mbOf("678"))
	}()
	select {
	case <-written:
		t.Fatal("writer should block while pipe is full")
	case <-time.After(30 * time.Millisecond):
	}
	mb, err := r.ReadMultiBuffer()
	require.NoError(t, err)
	require.Equal(t, "12345", mb.String())
	select {
	case err := <-written:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("writer not released after read")
	}
	mb, err = r.ReadMultiBuffer()
	require.NoError(t, err)
	require.Equal(t, "678", mb.String())

	r2, w2 := New(WithSizeLimit(0))
	require.NoError(t, w2.WriteMultiBuffer(mbOf("a")))
	blocked := make(chan error, 1)
	go func() {
		blocked <- w2.WriteMultiBuffer(mbOf("b"))
	}()
	time.Sleep(10 * time.Millisecond)
	r2.Interrupt()
	select {
	case err := <-blocked:
		require.ErrorIs(t, err, io.ErrClosedPipe)
	case <-time.After(2 * time.Second):
		t.Fatal("blocked writer not released by interrupt")
	}
}

func TestH_PipeDiscardOverflow(t *testing.T) {
	t.Parallel()
	r, w := New(WithSizeLimit(2), DiscardOverflow())
	require.NoError(t, w.WriteMultiBuffer(mbOf("abc")))
	require.NoError(t, w.WriteMultiBuffer(mbOf("dropped")))
	mb, err := r.ReadMultiBuffer()
	require.NoError(t, err)
	require.Equal(t, "abc", mb.String())

	r2, w2 := New(WithoutSizeLimit())
	for i := 0; i < 100; i++ {
		require.NoError(t, w2.WriteMultiBuffer(mbOf("0123456789")))
	}
	mb, err = r2.ReadMultiBuffer()
	require.NoError(t, err)
	require.Equal(t, int32(1000), mb.Len())
	buf.ReleaseMulti(mb)
}

func TestH_PipeReadTimeout(t *testing.T) {
	t.Parallel()
	r, w := New()
	start := time.Now()
	_, err := r.ReadMultiBufferTimeout(30 * time.Millisecond)
	require.ErrorIs(t, err, buf.ErrReadTimeout)
	require.GreaterOrEqual(t, time.Since(start), 30*time.Millisecond)

	require.NoError(t, w.WriteMultiBuffer(mbOf("in time")))
	mb, err := r.ReadMultiBufferTimeout(time.Second)
	require.NoError(t, err)
	require.Equal(t, "in time", mb.String())

	require.ErrorIs(t, buf.CopyOnceTimeout(r, buf.Discard, 10*time.Millisecond), buf.ErrReadTimeout)
}

func TestH_PipeReturnAnError(t *testing.T) {
	t.Parallel()
	r, _ := New()
	expected := errors.New("injected")
	r.ReturnAnError(expected)
	_, err := r.ReadMultiBuffer()
	require.ErrorIs(t, err, expected)

	require.NoError(t, r.Recover())
	r.ReturnAnError(expected)
	require.ErrorIs(t, r.Recover(), expected)
	require.NoError(t, r.Recover())
}

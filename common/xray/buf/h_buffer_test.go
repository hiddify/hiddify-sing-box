package buf

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestH_BufferReadWrite(t *testing.T) {
	t.Parallel()
	b := New()
	defer b.Release()
	require.True(t, b.IsEmpty())
	require.Equal(t, int32(Size), b.Cap())
	require.Equal(t, int32(Size), b.Available())

	n, err := b.WriteString("hello")
	require.NoError(t, err)
	require.Equal(t, 5, n)
	require.NoError(t, b.WriteByte('!'))
	require.Equal(t, "hello!", b.String())
	require.Equal(t, byte('e'), b.Byte(1))
	b.SetByte(0, 'H')
	require.Equal(t, "Hello!", b.String())

	c, err := b.ReadByte()
	require.NoError(t, err)
	require.Equal(t, byte('H'), c)
	got, err := b.ReadBytes(2)
	require.NoError(t, err)
	require.Equal(t, "el", string(got))
	_, err = b.ReadBytes(10)
	require.ErrorIs(t, err, io.EOF)

	p := make([]byte, 2)
	n, err = b.Read(p)
	require.NoError(t, err)
	require.Equal(t, "lo", string(p[:n]))
	n, err = b.Read(p)
	require.NoError(t, err)
	require.Equal(t, "!", string(p[:n]))
	require.True(t, b.IsEmpty())
	_, err = b.Read(p)
	require.ErrorIs(t, err, io.EOF)
	_, err = b.ReadByte()
	require.ErrorIs(t, err, io.EOF)
}

func TestH_BufferFull(t *testing.T) {
	t.Parallel()
	b := New()
	defer b.Release()
	data := make([]byte, Size+10)
	n, err := b.Write(data)
	require.ErrorIs(t, err, ErrBufferFull)
	require.Equal(t, Size, n)
	require.True(t, b.IsFull())
	require.ErrorIs(t, b.WriteByte(1), ErrBufferFull)
	require.Zero(t, b.Available())
}

func TestH_BufferSlicing(t *testing.T) {
	t.Parallel()
	b := New()
	defer b.Release()
	b.WriteString("0123456789")
	require.Equal(t, "234", string(b.BytesRange(2, 5)))
	require.Equal(t, "78", string(b.BytesRange(-3, -1)))
	require.Equal(t, "789", string(b.BytesFrom(-3)))
	require.Equal(t, "6789", string(b.BytesFrom(6)))
	require.Equal(t, "012", string(b.BytesTo(3)))
	require.Equal(t, "0123456", string(b.BytesTo(-3)))
	require.Empty(t, b.BytesTo(-100))

	b.Advance(2)
	require.Equal(t, "23456789", b.String())
	b.Advance(-2)
	require.Equal(t, "89", b.String())
	b.Advance(5)
	require.True(t, b.IsEmpty())

	b.Clear()
	b.WriteString("abcdef")
	b.Resize(1, 4)
	require.Equal(t, "bcd", b.String())
	b.Resize(0, 6)
	require.Equal(t, []byte{'b', 'c', 'd', 0, 0, 0}, b.Bytes())
	b.Resize(1, -1)
	require.Equal(t, []byte{'c', 'd', 0, 0}, b.Bytes())
	require.Panics(t, func() { b.Resize(3, 1) })

	b.Clear()
	b.WriteString("xy")
	ext := b.Extend(3)
	require.Equal(t, []byte{0, 0, 0}, ext)
	copy(ext, "zzz")
	require.Equal(t, "xyzzz", b.String())
	require.Panics(t, func() { b.Extend(Size) })
}

func TestH_BufferConstructorsAndRelease(t *testing.T) {
	t.Parallel()
	unmanaged := FromBytes([]byte("abc"))
	require.Equal(t, "abc", unmanaged.String())
	unmanaged.Release()
	require.Equal(t, "abc", unmanaged.String())

	existed := NewExisted(make([]byte, 3, Size))
	require.Equal(t, int32(3), existed.Len())
	require.Equal(t, int32(Size), existed.Cap())
	existed.Release()
	require.Zero(t, existed.Len())
	require.Panics(t, func() { NewExisted(make([]byte, 10)) })

	sized := NewWithSize(100)
	require.GreaterOrEqual(t, sized.Cap(), int32(100))
	sized.Release()
	large := NewWithSize(100000)
	require.GreaterOrEqual(t, large.Cap(), int32(100000))
	large.Release()

	stack := StackNew()
	stack.WriteString("s")
	require.Equal(t, "s", stack.String())
	stack.Release()

	var nilBuffer *Buffer
	require.Zero(t, nilBuffer.Len())
	require.Zero(t, nilBuffer.Cap())
	require.Zero(t, nilBuffer.Available())
	require.False(t, nilBuffer.IsFull())
	require.True(t, nilBuffer.IsEmpty())
	nilBuffer.Release()
}

func TestH_BufferReadFrom(t *testing.T) {
	t.Parallel()
	b := New()
	defer b.Release()
	n, err := b.ReadFullFrom(bytes.NewReader([]byte("abcdef")), 4)
	require.NoError(t, err)
	require.Equal(t, int64(4), n)
	require.Equal(t, "abcd", b.String())
	_, err = b.ReadFullFrom(bytes.NewReader(nil), Size)
	require.ErrorContains(t, err, "out of bound")
	n, err = b.ReadFullFrom(bytes.NewReader([]byte("x")), 2)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, int64(1), n)
	require.Equal(t, "abcdx", b.String())

	n, err = b.ReadFrom(bytes.NewReader([]byte("yz")))
	require.NoError(t, err)
	require.Equal(t, int64(2), n)
	require.Equal(t, "abcdxyz", b.String())
}

func TestH_MultiBufferSplitAndMerge(t *testing.T) {
	t.Parallel()
	payload := make([]byte, Size*2+100)
	rand.Read(payload)
	mb := MergeBytes(nil, payload)
	require.Len(t, mb, 3)
	require.Equal(t, int32(len(payload)), mb.Len())
	require.False(t, mb.IsEmpty())

	head := make([]byte, 10)
	require.Equal(t, 10, mb.Copy(head))
	require.Equal(t, payload[:10], head)

	mb = MergeBytes(mb, []byte("tail"))
	require.Len(t, mb, 3)
	payload = append(payload, "tail"...)

	rest, first := SplitSize(mb, 50)
	require.Equal(t, int32(50), first.Len())
	require.Equal(t, int32(len(payload)-50), rest.Len())
	firstBytes := make([]byte, 50)
	first.Copy(firstBytes)
	require.Equal(t, payload[:50], firstBytes)
	ReleaseMulti(first)

	rest, whole := SplitSize(rest, Size*2)
	require.Equal(t, int32(2*Size-50), whole.Len())
	ReleaseMulti(whole)

	out := make([]byte, rest.Len())
	rest, n := SplitBytes(rest, out)
	require.Equal(t, len(out), n)
	require.Empty(t, rest)
	require.Equal(t, payload[2*Size:], out)

	a := MultiBuffer{FromBytes([]byte("a"))}
	b := MultiBuffer{FromBytes([]byte("b")), FromBytes([]byte("c"))}
	merged, src := MergeMulti(a, b)
	require.Equal(t, "abc", merged.String())
	require.Empty(t, src)
	require.Nil(t, b[0])

	left, right := SplitMulti(merged, 1)
	require.Equal(t, "a", left.String())
	require.Equal(t, "bc", right.String())
	left, right = SplitMulti(MultiBuffer{FromBytes([]byte("z"))}, 5)
	require.Equal(t, "z", left.String())
	require.Empty(t, right)

	remaining, firstBuffer := SplitFirst(MultiBuffer{FromBytes([]byte("1")), FromBytes([]byte("2"))})
	require.Equal(t, "1", firstBuffer.String())
	require.Equal(t, "2", remaining.String())
	_, none := SplitFirst(nil)
	require.Nil(t, none)

	p := make([]byte, 4)
	remaining, n = SplitFirstBytes(MultiBuffer{FromBytes([]byte("12")), FromBytes([]byte("3"))}, p)
	require.Equal(t, 2, n)
	require.Equal(t, "12", string(p[:n]))
	require.Equal(t, "3", remaining.String())
	_, n = SplitFirstBytes(nil, p)
	require.Zero(t, n)

	var nilMB MultiBuffer
	require.Zero(t, nilMB.Len())
	require.True(t, nilMB.IsEmpty())
	require.True(t, MultiBuffer{New()}.IsEmpty())
}

func TestH_Compact(t *testing.T) {
	t.Parallel()
	var mb MultiBuffer
	for i := 0; i < 10; i++ {
		b := New()
		b.WriteString("0123456789")
		mb = append(mb, b)
	}
	big := New()
	big.Extend(Size - 10)
	mb = append(mb, big)
	compacted := Compact(mb)
	require.Len(t, compacted, 2)
	require.Equal(t, int32(100), compacted[0].Len())
	require.Equal(t, int32(Size-10), compacted[1].Len())
	ReleaseMulti(compacted)
	require.Empty(t, Compact(nil))
}

func TestH_ReadFromAndReadAllToBytes(t *testing.T) {
	t.Parallel()
	payload := make([]byte, Size*3+7)
	rand.Read(payload)
	mb, err := ReadFrom(bytes.NewReader(payload))
	require.NoError(t, err)
	require.Len(t, mb, 4)
	require.Equal(t, int32(len(payload)), mb.Len())
	ReleaseMulti(mb)

	all, err := ReadAllToBytes(bytes.NewReader(payload))
	require.NoError(t, err)
	require.Equal(t, payload, all)

	all, err = ReadAllToBytes(bytes.NewReader(nil))
	require.NoError(t, err)
	require.Nil(t, all)
}

func TestH_MultiBufferContainer(t *testing.T) {
	t.Parallel()
	c := &MultiBufferContainer{}
	n, err := c.Write([]byte("hello "))
	require.NoError(t, err)
	require.Equal(t, 6, n)
	require.NoError(t, c.WriteMultiBuffer(MultiBuffer{FromBytes([]byte("world"))}))
	p := make([]byte, 3)
	n, err = c.Read(p)
	require.NoError(t, err)
	require.Equal(t, "hel", string(p[:n]))
	mb, err := c.ReadMultiBuffer()
	require.NoError(t, err)
	require.Equal(t, "lo world", mb.String())
	_, err = c.Read(p)
	require.ErrorIs(t, err, io.EOF)
	c.Write([]byte("x"))
	require.NoError(t, c.Close())
	require.True(t, c.IsEmpty())
}

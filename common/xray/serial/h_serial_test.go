package serial

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestH_Uint16Uint64(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	n, err := WriteUint16(&buf, 0xabcd)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	n, err = WriteUint64(&buf, 0x0102030405060708)
	require.NoError(t, err)
	require.Equal(t, 8, n)
	require.Equal(t, []byte{0xab, 0xcd, 1, 2, 3, 4, 5, 6, 7, 8}, buf.Bytes())

	v, err := ReadUint16(&buf)
	require.NoError(t, err)
	require.Equal(t, uint16(0xabcd), v)
	_, err = ReadUint16(bytes.NewReader([]byte{1}))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	_, err = ReadUint16(bytes.NewReader(nil))
	require.ErrorIs(t, err, io.EOF)
}

type stringer struct{}

func (stringer) String() string { return "stringer" }

func TestH_ToStringAndConcat(t *testing.T) {
	t.Parallel()
	s := "ptr"
	require.Equal(t, "", ToString(nil))
	require.Equal(t, "plain", ToString("plain"))
	require.Equal(t, "ptr", ToString(&s))
	require.Equal(t, "stringer", ToString(stringer{}))
	require.Equal(t, "err", ToString(errors.New("err")))
	require.Equal(t, "42", ToString(42))
	require.Equal(t, "{A:1}", ToString(struct{ A int }{1}))
	require.Equal(t, "a1stringer", Concat("a", 1, nil, stringer{}))
	require.Equal(t, "", Concat())
}

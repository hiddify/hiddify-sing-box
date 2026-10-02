package adapter

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/sagernet/sing/common/varbin"

	"github.com/stretchr/testify/require"
)

func TestH_SavedBinaryRoundTrip(t *testing.T) {
	t.Parallel()
	cases := []SavedBinary{
		{Content: []byte("rule-set content"), LastUpdated: time.Unix(1700000000, 0), LastEtag: `W/"abc"`, URLHash: bytes.Repeat([]byte{0xab}, 32)},
		{Content: []byte{}, LastUpdated: time.Unix(0, 0), LastEtag: "", URLHash: []byte{}},
		{Content: bytes.Repeat([]byte{0x01, 0x02}, 1000), LastUpdated: time.Unix(1, 0), LastEtag: "etag"},
	}
	for _, saved := range cases {
		data, err := saved.MarshalBinary()
		require.NoError(t, err)
		require.Equal(t, byte(2), data[0])
		var decoded SavedBinary
		require.NoError(t, decoded.UnmarshalBinary(data))
		require.Equal(t, saved.Content, decoded.Content)
		require.Equal(t, saved.LastUpdated.Unix(), decoded.LastUpdated.Unix())
		require.Equal(t, saved.LastEtag, decoded.LastEtag)
		require.Equal(t, len(saved.URLHash), len(decoded.URLHash))
		if len(saved.URLHash) > 0 {
			require.Equal(t, saved.URLHash, decoded.URLHash)
		}
	}
}

func TestH_SavedBinaryVersion1(t *testing.T) {
	t.Parallel()
	var buffer bytes.Buffer
	buffer.WriteByte(1)
	_, _ = varbin.WriteUvarint(&buffer, 3)
	buffer.WriteString("abc")
	_ = binary.Write(&buffer, binary.BigEndian, int64(42))
	_, _ = varbin.WriteUvarint(&buffer, 2)
	buffer.WriteString("e1")
	var decoded SavedBinary
	require.NoError(t, decoded.UnmarshalBinary(buffer.Bytes()))
	require.Equal(t, []byte("abc"), decoded.Content)
	require.Equal(t, int64(42), decoded.LastUpdated.Unix())
	require.Equal(t, "e1", decoded.LastEtag)
	require.Nil(t, decoded.URLHash)
}

func TestH_SavedBinaryMalformed(t *testing.T) {
	t.Parallel()
	saved := SavedBinary{Content: []byte("content"), LastUpdated: time.Unix(5, 0), LastEtag: "etag", URLHash: []byte{1, 2, 3}}
	data, err := saved.MarshalBinary()
	require.NoError(t, err)
	for i := 0; i < len(data); i++ {
		var decoded SavedBinary
		require.Error(t, decoded.UnmarshalBinary(data[:i]), "truncated at %d", i)
	}
	var decoded SavedBinary
	require.ErrorContains(t, decoded.UnmarshalBinary([]byte{2, 0xff, 0xff, 0x03}), "invalid content length")
}

func TestH_InboundContextRealOutbound(t *testing.T) {
	t.Parallel()
	var metadata InboundContext
	require.Empty(t, metadata.GetRealOutbound())
	metadata.SetRealOutbound("proxy-a")
	require.Equal(t, "proxy-a", metadata.GetRealOutbound())
	require.Equal(t, "proxy-a", metadata.RealOutbound)
	metadata.ResetRuleCache()
	require.Equal(t, "proxy-a", metadata.GetRealOutbound())
}

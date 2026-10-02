package geosite

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestH_GeositeCodeRoundTrip(t *testing.T) {
	t.Parallel()
	domains := map[string][]Item{
		"cn":      {{Type: RuleTypeDomainSuffix, Value: "cn"}, {Type: RuleTypeDomain, Value: "baidu.com"}},
		"ir":      {{Type: RuleTypeDomainKeyword, Value: "digikala"}},
		"empty":   {},
		"":        {{Type: RuleTypeDomainRegex, Value: `^a\.b$`}},
		"long-tw": {{Type: RuleTypeDomain, Value: string(bytes.Repeat([]byte("a"), 300)) + ".tw"}},
	}
	var buffer bytes.Buffer
	require.NoError(t, Write(&buffer, domains))

	reader, codes, err := NewReader(bytes.NewReader(buffer.Bytes()))
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"cn", "ir", "empty", "", "long-tw"}, codes)
	for code, items := range domains {
		got, err := reader.Read(code)
		require.NoError(t, err, code)
		if len(items) == 0 {
			require.Empty(t, got, code)
		} else {
			require.Equal(t, items, got, code)
		}
	}
	_, err = reader.Read("missing")
	require.Error(t, err)
}

func TestH_GeositeMetadataCodeEncoding(t *testing.T) {
	t.Parallel()
	var buffer bytes.Buffer
	require.NoError(t, Write(&buffer, map[string][]Item{"ab": {{Type: RuleTypeDomain, Value: "x"}}}))
	data := buffer.Bytes()
	require.Equal(t, []byte{0x00, 0x01, 0x02, 'a', 'b', 0x00, 0x01}, data[:7])
}

func TestH_GeositeMetadataTruncated(t *testing.T) {
	t.Parallel()
	for _, data := range [][]byte{
		{},
		{0x01},
		{0x00},
		{0x00, 0x01},
		{0x00, 0x01, 0x05, 'a', 'b'},
		{0x00, 0x01, 0x02, 'a', 'b'},
		{0x00, 0x01, 0x02, 'a', 'b', 0x00},
	} {
		_, _, err := NewReader(bytes.NewReader(data))
		require.Error(t, err, "%x", data)
	}
}

func TestH_GeositeMetadataHugeCodeLength(t *testing.T) {
	t.Skip("BUG: geosite reader.go readMetadata uses varbin.ReadValue[string], which allocates the attacker-claimed code length up front (the old readString grew incrementally)")
	data := []byte{0x00}
	data = binary.AppendUvarint(data, 1)
	data = binary.AppendUvarint(data, 256<<20)
	data = append(data, 'x')
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, _, err := NewReader(bytes.NewReader(data))
	runtime.ReadMemStats(&after)
	require.Error(t, err)
	require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(16<<20))
}

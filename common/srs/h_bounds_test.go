package srs

import (
	"bufio"
	"bytes"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

func hReader(parts ...[]byte) *bufio.Reader {
	return bufio.NewReader(bytes.NewReader(bytes.Join(parts, nil)))
}

func hAllocatedDuring(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestH_ReadRuleItemStringBounds(t *testing.T) {
	t.Parallel()
	_, err := readRuleItemString(hReader(uvarint(maxRuleItemCount + 1)))
	require.ErrorContains(t, err, "too many rule item strings")

	_, err = readRuleItemString(hReader(uvarint(1<<62), []byte("x")))
	require.ErrorContains(t, err, "too many rule item strings")

	_, err = readRuleItemString(hReader(uvarint(1), uvarint(maxRuleItemStringLength+1)))
	require.ErrorContains(t, err, "rule item string too long")

	_, err = readRuleItemString(hReader(uvarint(2), uvarint(1), []byte("a"), uvarint(1<<40)))
	require.ErrorContains(t, err, "rule item string too long")

	_, err = readRuleItemString(hReader(uvarint(1), uvarint(16), []byte("short")))
	require.ErrorContains(t, err, "string value")

	_, err = readRuleItemString(hReader(uvarint(3), uvarint(1), []byte("a")))
	require.ErrorContains(t, err, "string length")

	_, err = readRuleItemString(hReader())
	require.ErrorContains(t, err, "slice length")

	_, err = readRuleItemString(hReader([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}))
	require.Error(t, err)
}

func TestH_ReadRuleItemStringValid(t *testing.T) {
	t.Parallel()
	result, err := readRuleItemString(hReader(uvarint(0)))
	require.NoError(t, err)
	require.Nil(t, result)

	result, err = readRuleItemString(hReader(uvarint(3), uvarint(3), []byte("foo"), uvarint(0), uvarint(4), []byte("barz")))
	require.NoError(t, err)
	require.Equal(t, []string{"foo", "", "barz"}, result)
}

func TestH_ReadRuleItemUint8Bounds(t *testing.T) {
	t.Parallel()
	_, err := readRuleItemUint8[uint8](hReader(uvarint(maxRuleItemCount + 1)))
	require.ErrorContains(t, err, "too many rule item values")

	_, err = readRuleItemUint8[uint8](hReader(uvarint(1 << 40)))
	require.ErrorContains(t, err, "too many rule item values")

	_, err = readRuleItemUint8[uint8](hReader(uvarint(4), []byte{1, 2}))
	require.Error(t, err)

	_, err = readRuleItemUint8[uint8](hReader())
	require.ErrorContains(t, err, "slice length")

	result, err := readRuleItemUint8[uint8](hReader(uvarint(0)))
	require.NoError(t, err)
	require.Nil(t, result)

	type custom uint8
	typed, err := readRuleItemUint8[custom](hReader(uvarint(3), []byte{7, 0, 255}))
	require.NoError(t, err)
	require.Equal(t, []custom{7, 0, 255}, typed)
}

func TestH_ReadRuleItemUint16Bounds(t *testing.T) {
	t.Parallel()
	_, err := readRuleItemUint16(hReader(uvarint(maxRuleItemCount + 1)))
	require.ErrorContains(t, err, "too many rule item values")

	_, err = readRuleItemUint16(hReader(uvarint(1 << 40)))
	require.ErrorContains(t, err, "too many rule item values")

	_, err = readRuleItemUint16(hReader(uvarint(2), []byte{0, 1, 0}))
	require.Error(t, err)

	_, err = readRuleItemUint16(hReader())
	require.ErrorContains(t, err, "slice length")

	result, err := readRuleItemUint16(hReader(uvarint(0)))
	require.NoError(t, err)
	require.Nil(t, result)

	result, err = readRuleItemUint16(hReader(uvarint(2), []byte{0x01, 0xbb, 0x00, 0x35}))
	require.NoError(t, err)
	require.Equal(t, []uint16{443, 53}, result)
}

func TestH_ReadRuleItemWriterRoundTrip(t *testing.T) {
	t.Parallel()
	var buffer bytes.Buffer
	writer := bufio.NewWriter(&buffer)
	require.NoError(t, writeRuleItemString(writer, ruleItemDomainKeyword, []string{"alpha", "", "gamma"}))
	require.NoError(t, writeRuleItemUint8(writer, ruleItemNetworkType, []uint8{1, 2, 3}))
	require.NoError(t, writeRuleItemUint16(writer, ruleItemPort, []uint16{80, 443, 65535}))
	require.NoError(t, writer.Flush())

	reader := bufio.NewReader(&buffer)
	itemType, err := reader.ReadByte()
	require.NoError(t, err)
	require.Equal(t, ruleItemDomainKeyword, itemType)
	strings, err := readRuleItemString(reader)
	require.NoError(t, err)
	require.Equal(t, []string{"alpha", "", "gamma"}, strings)

	itemType, err = reader.ReadByte()
	require.NoError(t, err)
	require.Equal(t, ruleItemNetworkType, itemType)
	values8, err := readRuleItemUint8[uint8](reader)
	require.NoError(t, err)
	require.Equal(t, []uint8{1, 2, 3}, values8)

	itemType, err = reader.ReadByte()
	require.NoError(t, err)
	require.Equal(t, ruleItemPort, itemType)
	values16, err := readRuleItemUint16(reader)
	require.NoError(t, err)
	require.Equal(t, []uint16{80, 443, 65535}, values16)
}

func TestH_ReadOversizedRuleItemsFast(t *testing.T) {
	defaultRule := []byte{0x00}
	stringItems := []uint8{
		ruleItemNetwork, ruleItemDomainKeyword, ruleItemDomainRegex, ruleItemSourcePortRange,
		ruleItemPortRange, ruleItemProcessName, ruleItemProcessPath, ruleItemProcessPathRegex,
		ruleItemPackageName, ruleItemPackageNameRegex, ruleItemWIFISSID, ruleItemWIFIBSSID,
	}
	for _, item := range stringItems {
		for _, body := range [][]byte{
			bytes.Join([][]byte{uvarint(1), defaultRule, {item}, uvarint(maxRuleItemCount + 1)}, nil),
			bytes.Join([][]byte{uvarint(1), defaultRule, {item}, uvarint(1), uvarint(maxRuleItemStringLength + 1)}, nil),
			bytes.Join([][]byte{uvarint(1), defaultRule, {item}, uvarint(1), uvarint(1 << 40)}, nil),
		} {
			data := craftRuleSet(body)
			start := time.Now()
			var readErr error
			allocated := hAllocatedDuring(func() {
				_, readErr = Read(bytes.NewReader(data), false)
			})
			require.Error(t, readErr, "item %d", item)
			require.Less(t, time.Since(start), 2*time.Second, "item %d", item)
			require.Less(t, allocated, uint64(64<<20), "item %d allocated %d bytes", item, allocated)
		}
	}
}

func TestH_ReadAtBoundaryTruncated(t *testing.T) {
	t.Parallel()
	defaultRule := []byte{0x00}
	_, err := Read(bytes.NewReader(craftRuleSet(bytes.Join([][]byte{
		uvarint(1), defaultRule, {ruleItemDomainKeyword}, uvarint(1), uvarint(maxRuleItemStringLength),
	}, nil))), false)
	require.Error(t, err)

	_, err = Read(bytes.NewReader(craftRuleSet(bytes.Join([][]byte{
		uvarint(1), defaultRule, {ruleItemDomainKeyword}, uvarint(maxRuleItemCount),
	}, nil))), false)
	require.Error(t, err)
}

func TestH_WriteReadStringItemsRoundTrip(t *testing.T) {
	t.Parallel()
	rule := option.DefaultHeadlessRule{
		Network:          badoption.Listable[string]{"tcp", "udp"},
		DomainKeyword:    badoption.Listable[string]{"google", "hiddify"},
		DomainRegex:      badoption.Listable[string]{`^.+\.example\.com$`},
		SourcePortRange:  badoption.Listable[string]{"1000:2000"},
		PortRange:        badoption.Listable[string]{":3000"},
		ProcessName:      badoption.Listable[string]{"curl"},
		ProcessPath:      badoption.Listable[string]{"/usr/bin/curl"},
		ProcessPathRegex: badoption.Listable[string]{`^/usr/.*`},
		PackageName:      badoption.Listable[string]{"app.hiddify.com"},
		WIFISSID:         badoption.Listable[string]{"home"},
		WIFIBSSID:        badoption.Listable[string]{"00:11:22:33:44:55"},
		Port:             badoption.Listable[uint16]{443},
		SourcePort:       badoption.Listable[uint16]{1234},
	}
	ruleSet := option.PlainRuleSet{Rules: []option.HeadlessRule{{Type: "default", DefaultOptions: rule}}}
	var buffer bytes.Buffer
	require.NoError(t, Write(&buffer, ruleSet, 1))
	decoded, err := Read(bytes.NewReader(buffer.Bytes()), true)
	require.NoError(t, err)
	require.Len(t, decoded.Options.Rules, 1)
	got := decoded.Options.Rules[0].DefaultOptions
	require.Equal(t, rule.Network, got.Network)
	require.Equal(t, rule.DomainKeyword, got.DomainKeyword)
	require.Equal(t, rule.DomainRegex, got.DomainRegex)
	require.Equal(t, rule.SourcePortRange, got.SourcePortRange)
	require.Equal(t, rule.PortRange, got.PortRange)
	require.Equal(t, rule.ProcessName, got.ProcessName)
	require.Equal(t, rule.ProcessPath, got.ProcessPath)
	require.Equal(t, rule.ProcessPathRegex, got.ProcessPathRegex)
	require.Equal(t, rule.PackageName, got.PackageName)
	require.Equal(t, rule.WIFISSID, got.WIFISSID)
	require.Equal(t, rule.WIFIBSSID, got.WIFIBSSID)
	require.Equal(t, rule.Port, got.Port)
	require.Equal(t, rule.SourcePort, got.SourcePort)
}

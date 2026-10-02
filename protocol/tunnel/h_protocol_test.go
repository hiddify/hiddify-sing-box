package tunnel

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/gofrs/uuid/v5"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

var (
	hUUIDA = uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))
	hUUIDB = uuid.Must(uuid.FromString("22222222-2222-2222-2222-222222222222"))
	hUUIDC = uuid.Must(uuid.FromString("33333333-3333-3333-3333-333333333333"))
)

func TestH_RequestRoundTrip(t *testing.T) {
	t.Parallel()
	destinations := []M.Socksaddr{
		M.SocksaddrFrom(netip.MustParseAddr("192.0.2.1"), 80),
		M.SocksaddrFrom(netip.MustParseAddr("2001:db8::1"), 443),
		{Fqdn: "example.com", Port: 8080},
		Destination,
	}
	for _, command := range []byte{CommandInbound, CommandTCP} {
		for _, destination := range destinations {
			request := &Request{UUID: hUUIDA, Command: command, DestinationUUID: hUUIDB, Destination: destination}
			var buffer bytes.Buffer
			require.NoError(t, WriteRequest(&buffer, request))
			require.Equal(t, 1+16+1+16+AddressSerializer.AddrPortLen(destination), buffer.Len())
			require.Equal(t, byte(Version), buffer.Bytes()[0])
			decoded, err := ReadRequest(&buffer)
			require.NoError(t, err)
			require.Equal(t, request, decoded)
			require.Zero(t, buffer.Len())
		}
	}
}

func TestH_RequestWireLayout(t *testing.T) {
	t.Parallel()
	var buffer bytes.Buffer
	require.NoError(t, WriteRequest(&buffer, &Request{
		UUID:            hUUIDA,
		Command:         CommandTCP,
		DestinationUUID: hUUIDB,
		Destination:     M.SocksaddrFrom(netip.MustParseAddr("10.0.0.1"), 0x1234),
	}))
	data := buffer.Bytes()
	require.Equal(t, byte(0), data[0])
	require.Equal(t, hUUIDA.Bytes(), data[1:17])
	require.Equal(t, byte(CommandTCP), data[17])
	require.Equal(t, hUUIDB.Bytes(), data[18:34])
	require.Equal(t, []byte{0x12, 0x34, 0x01, 10, 0, 0, 1}, data[34:])
}

func TestH_ReadRequestInvalid(t *testing.T) {
	t.Parallel()
	var valid bytes.Buffer
	require.NoError(t, WriteRequest(&valid, &Request{UUID: hUUIDA, Command: CommandTCP, DestinationUUID: hUUIDB, Destination: Destination}))
	raw := valid.Bytes()

	_, err := ReadRequest(bytes.NewReader(nil))
	require.Error(t, err)

	badVersion := append([]byte{1}, raw[1:]...)
	_, err = ReadRequest(bytes.NewReader(badVersion))
	require.ErrorContains(t, err, "unknown version")

	for _, n := range []int{1, 10, 17, 18, 30, 34, 36, len(raw) - 1} {
		_, err = ReadRequest(bytes.NewReader(raw[:n]))
		require.Error(t, err, "truncated at %d", n)
	}

	badFamily := append([]byte(nil), raw...)
	badFamily[36] = 0x7f
	_, err = ReadRequest(bytes.NewReader(badFamily))
	require.Error(t, err)
}

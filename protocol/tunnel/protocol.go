package tunnel

import (
	"encoding/binary"
	"io"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	Version = 0
)

const (
	CommandInbound = 1
	CommandTCP     = 2
)

var Destination = M.Socksaddr{
	Fqdn: "sp.tunnel.sing-box.arpa",
	Port: 444,
}

var AddressSerializer = M.NewSerializer(
	M.AddressFamilyByte(0x01, M.AddressFamilyIPv4),
	M.AddressFamilyByte(0x03, M.AddressFamilyIPv6),
	M.AddressFamilyByte(0x02, M.AddressFamilyFqdn),
	M.PortThenAddress(),
)

type Request struct {
	UUID            uuid.UUID
	Command         byte
	DestinationUUID uuid.UUID
	Destination     M.Socksaddr
}

func ReadRequest(reader io.Reader) (*Request, error) {
	var request Request
	var version uint8
	err := binary.Read(reader, binary.BigEndian, &version)
	if err != nil {
		return nil, err
	}
	if version != Version {
		return nil, E.New("unknown version: ", version)
	}
	_, err = io.ReadFull(reader, request.UUID[:])
	if err != nil {
		return nil, err
	}
	err = binary.Read(reader, binary.BigEndian, &request.Command)
	if err != nil {
		return nil, err
	}
	_, err = io.ReadFull(reader, request.DestinationUUID[:])
	if err != nil {
		return nil, err
	}
	request.Destination, err = AddressSerializer.ReadAddrPort(reader)
	if err != nil {
		return nil, err
	}
	return &request, nil
}

func WriteRequest(writer io.Writer, request *Request) error {
	var requestLen int
	requestLen += 1  // version
	requestLen += 16 // UUID
	requestLen += 16 // destinationUUID
	requestLen += 1  // command
	requestLen += AddressSerializer.AddrPortLen(request.Destination)
	buffer := buf.NewSize(requestLen)
	defer buffer.Release()
	common.Must(
		buffer.WriteByte(Version),
		common.Error(buffer.Write(request.UUID[:])),
		buffer.WriteByte(request.Command),
		common.Error(buffer.Write(request.DestinationUUID[:])),
	)
	err := AddressSerializer.WriteAddrPort(buffer, request.Destination)
	if err != nil {
		return err
	}
	return common.Error(writer.Write(buffer.Bytes()))
}

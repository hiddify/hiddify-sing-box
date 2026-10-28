package obfs

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"time"

	B "github.com/sagernet/sing/common/buf"
)

// TLSObfsServer is the server-side simple-obfs TLS implementation.
// It reads the client's fake ClientHello and writes a fake ServerHello.
type TLSObfsServer struct {
	net.Conn
	hosts         []string //H obfs_host; empty allows any
	remain        int
	pending       []byte
	handshakeDone bool
	firstResponse bool
}

// Byte layout of the fake ClientHello written by makeClientHelloMsg.
const (
	tlsHelloFixedLength = 133 // handshake header up to and including compression methods
	tlsHelloTailLength  = 66  // ec_point_formats, groups, signature_algorithms, encrypt_then_mac, extended_master_secret
	tlsCipherSuitesSize = 0x38
)

func (tos *TLSObfsServer) read(b []byte, discardN int) (int, error) {
	discard := B.Get(discardN)
	_, err := io.ReadFull(tos.Conn, discard)
	B.Put(discard)
	if err != nil {
		return 0, err
	}

	sizeBuf := make([]byte, 2)
	_, err = io.ReadFull(tos.Conn, sizeBuf)
	if err != nil {
		return 0, err
	}

	length := int(binary.BigEndian.Uint16(sizeBuf))
	if length > len(b) {
		n, err := tos.Conn.Read(b)
		if err != nil {
			return n, err
		}
		tos.remain = length - n
		return n, nil
	}

	return io.ReadFull(tos.Conn, b[:length])
}

// handshake reads the whole fake ClientHello record and keeps the payload carried
// in its session ticket. It returns every byte it read, so that a connection that
// is not simple-obfs can be replayed to a fallback server.
func (tos *TLSObfsServer) handshake() ([]byte, error) {
	tos.handshakeDone = true
	header := make([]byte, 5)
	n, err := io.ReadFull(tos.Conn, header)
	if err != nil {
		return header[:n], err
	}
	if header[0] != 0x16 || header[1] != 0x03 {
		return header, ErrNotObfs
	}
	recordLength := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLength < tlsHelloFixedLength+4+9+tlsHelloTailLength {
		return header, ErrNotObfs
	}
	record := make([]byte, 5+recordLength)
	copy(record, header)
	n, err = io.ReadFull(tos.Conn, record[5:])
	if err != nil {
		return record[:5+n], err
	}
	payload, serverName, err := parseTLSObfsClientHello(record[5:])
	if err != nil {
		return record, err
	}
	if !hostAllowed(serverName, tos.hosts) { //H obfs_host
		return record, ErrNotObfs
	}
	tos.pending = payload
	return nil, nil
}

// parseTLSObfsClientHello checks that hello has the exact layout of the simple-obfs
// ClientHello and returns the payload carried in the session ticket extension.
func parseTLSObfsClientHello(hello []byte) ([]byte, string, error) {
	if hello[0] != 0x01 || int(hello[1])<<16|int(hello[2])<<8|int(hello[3]) != len(hello)-4 {
		return nil, "", ErrNotObfs
	}
	if hello[4] != 0x03 || hello[5] != 0x03 || hello[38] != 32 {
		return nil, "", ErrNotObfs
	}
	if binary.BigEndian.Uint16(hello[71:73]) != tlsCipherSuitesSize || hello[129] != 0x01 || hello[130] != 0x00 {
		return nil, "", ErrNotObfs
	}
	if int(binary.BigEndian.Uint16(hello[131:133])) != len(hello)-tlsHelloFixedLength {
		return nil, "", ErrNotObfs
	}
	extensions := hello[tlsHelloFixedLength:]
	if binary.BigEndian.Uint16(extensions[0:2]) != 0x0023 {
		return nil, "", ErrNotObfs
	}
	ticketLength := int(binary.BigEndian.Uint16(extensions[2:4]))
	if ticketLength == 0 || 4+ticketLength+9 > len(extensions) {
		return nil, "", ErrNotObfs
	}
	payload := extensions[4 : 4+ticketLength]
	serverName := extensions[4+ticketLength:]
	nameLength := int(binary.BigEndian.Uint16(serverName[7:9]))
	if binary.BigEndian.Uint16(serverName[0:2]) != 0x0000 ||
		int(binary.BigEndian.Uint16(serverName[2:4])) != nameLength+5 ||
		int(binary.BigEndian.Uint16(serverName[4:6])) != nameLength+3 ||
		serverName[6] != 0 ||
		len(serverName) != 9+nameLength+tlsHelloTailLength {
		return nil, "", ErrNotObfs
	}
	return payload, string(serverName[9 : 9+nameLength]), nil
}

func (tos *TLSObfsServer) Read(b []byte) (int, error) {
	if !tos.handshakeDone {
		if _, err := tos.handshake(); err != nil {
			return 0, err
		}
	}

	if len(tos.pending) > 0 {
		n := copy(b, tos.pending)
		tos.pending = tos.pending[n:]
		return n, nil
	}

	if tos.remain > 0 {
		length := tos.remain
		if length > len(b) {
			length = len(b)
		}
		n, err := io.ReadFull(tos.Conn, b[:length])
		tos.remain -= n
		return n, err
	}

	return tos.read(b, 3)
}

func (tos *TLSObfsServer) Write(b []byte) (int, error) {
	length := len(b)
	for i := 0; i < length; i += chunkSize {
		end := i + chunkSize
		if end > length {
			end = length
		}
		if _, err := tos.write(b[i:end]); err != nil {
			return i, err
		}
	}
	return length, nil
}

func (tos *TLSObfsServer) write(b []byte) (int, error) {
	if tos.firstResponse {
		serverHello := makeTLSServerHello(b)
		_, err := tos.Conn.Write(serverHello)
		tos.firstResponse = false
		return len(b), err
	}

	buf := B.NewSize(5 + len(b))
	defer buf.Release()
	buf.Write([]byte{0x17, 0x03, 0x03})
	binary.Write(buf, binary.BigEndian, uint16(len(b)))
	buf.Write(b)
	_, err := tos.Conn.Write(buf.Bytes())
	return len(b), err
}

func (tos *TLSObfsServer) Upstream() any {
	return tos.Conn
}

// NewTLSObfsServer wraps conn with server-side TLS obfs.
func NewTLSObfsServer(conn net.Conn) net.Conn {
	return &TLSObfsServer{
		Conn:          conn,
		firstResponse: true,
	}
}

func makeTLSServerHello(data []byte) []byte {
	randBytes := make([]byte, 28)
	sessionID := make([]byte, 32)
	rand.Read(randBytes)
	rand.Read(sessionID)

	buf := &bytes.Buffer{}

	// ServerHello record
	buf.WriteByte(0x16)
	binary.Write(buf, binary.BigEndian, uint16(0x0301))
	binary.Write(buf, binary.BigEndian, uint16(91))
	buf.Write([]byte{2, 0, 0, 87, 0x03, 0x03})
	binary.Write(buf, binary.BigEndian, uint32(time.Now().Unix()))
	buf.Write(randBytes)
	buf.WriteByte(32)
	buf.Write(sessionID)
	buf.Write([]byte{0xcc, 0xa8})
	buf.WriteByte(0)
	buf.Write([]byte{0x00, 0x00})
	buf.Write([]byte{0xff, 0x01, 0x00, 0x01, 0x00})
	buf.Write([]byte{0x00, 0x17, 0x00, 0x00})
	buf.Write([]byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00})

	// ChangeCipherSpec
	buf.Write([]byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01})

	// Finished (carrying the first payload)
	buf.Write([]byte{0x16, 0x03, 0x03})
	binary.Write(buf, binary.BigEndian, uint16(len(data)))
	buf.Write(data)

	return buf.Bytes()
}

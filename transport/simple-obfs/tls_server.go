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
	remain            int
	firstRequest      bool
	sessionTicketDone bool
	firstResponse     bool
}

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
		return 0, nil
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

// skipOtherExts discards SNI and other TLS extensions after session ticket.
func (tos *TLSObfsServer) skipOtherExts() error {
	buf := make([]byte, 256)
	_, err := tos.read(buf, 7)
	if err != nil {
		return err
	}
	_, err = io.ReadFull(tos.Conn, buf[:4*16+2])
	return err
}

func (tos *TLSObfsServer) Read(b []byte) (int, error) {
	if tos.remain > 0 {
		length := tos.remain
		if length > len(b) {
			length = len(b)
		}
		n, err := io.ReadFull(tos.Conn, b[:length])
		tos.remain -= n
		return n, err
	}

	if tos.firstRequest {
		tos.firstRequest = false
		// Skip: record header(5) + handshake header(4) + TLS version(2) + timestamp(4) + random(28) + sid_len(1) + sid(32) + cipher_suites_len(2) + ciphers(56) + compress(2) = 9*16-4 = 140 bytes
		return tos.read(b, 9*16-4)
	}

	if !tos.sessionTicketDone {
		tos.sessionTicketDone = true
		if err := tos.skipOtherExts(); err != nil {
			return 0, err
		}
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
		firstRequest:  true,
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

package shadowsocks

import (
	"net"

	"github.com/sagernet/sing-box/hiddify/readahead"
	"github.com/sagernet/sing-shadowsocks2"
	"github.com/sagernet/sing-shadowsocks2/shadowaead"
)

// hBatch gives an AEAD connection read ahead a reader that hands on the chunks already read in
// one buffer, so they reach the application in one write (see package readahead). An AEAD chunk
// is at most shadowaead.MaxPacketSize bytes, with its encrypted length and two tags on the wire.
func hBatch(method shadowsocks.Method, conn net.Conn, ahead net.Conn) net.Conn {
	if _, isAEAD := method.(*shadowaead.Method); !isAEAD {
		return conn
	}
	return readahead.Batch(conn, ahead, 2+16+shadowaead.MaxPacketSize+16, shadowaead.MaxPacketSize)
}

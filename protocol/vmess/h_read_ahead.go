package vmess

import (
	"net"

	"github.com/sagernet/sing-box/hiddify/readahead"
)

// hReadAhead is the connection the client reads its chunks from: straight over TCP, a socket read
// ahead 64 KB at a time (see package readahead), instead of two system calls a chunk.
func hReadAhead(conn net.Conn, err error) net.Conn {
	if err != nil || conn == nil {
		return conn
	}
	return readahead.New(conn)
}

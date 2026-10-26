package shadowsocks

import (
	"context"
	"net"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-shadowsocks2"
	M "github.com/sagernet/sing/common/metadata"
)

// dialShadowsocks2022 writes the SS2022 request header before returning the connection. SS2022
// saves the request salt at the end of its first write and checks the response against it, so a
// reader that starts while an early first write is still going (the download side of a relay)
// failed with "bad request salt". The handshake is bounded by the dial context and the TCP
// timeout, and closes the connection on failure.
//
// From reF1nd/sing-box e08591f7.
func dialShadowsocks2022(ctx context.Context, method shadowsocks.Method, outConn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	handshakeCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	defer cancel()
	closed := make(chan struct{})
	stop := context.AfterFunc(handshakeCtx, func() {
		outConn.Close()
		close(closed)
	})
	conn, err := method.DialConn(outConn, destination)
	if !stop() {
		<-closed
	}
	if handshakeCtx.Err() != nil {
		err = handshakeCtx.Err()
	}
	if err != nil {
		outConn.Close()
		return nil, err
	}
	return conn, nil
}

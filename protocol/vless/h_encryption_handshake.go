package vless

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/protocol/vless/encryption"
)

// encryptionHandshake runs the VLESS encryption handshake, which takes no context and in 1-RTT
// mode waits for the server's reply, so a server that accepts and never answers held it for
// good. Close the connection when ctx ends first; the caller closes it on any error anyway.
// Close, not a deadline: transport connections (XHTTP, gRPC) may ignore deadlines.
func encryptionHandshake(ctx context.Context, instance *encryption.ClientInstance, conn net.Conn) (net.Conn, error) {
	stop := context.AfterFunc(ctx, func() {
		conn.Close()
	})
	encryptedConn, err := instance.Handshake(conn)
	if !stop() {
		return nil, context.Cause(ctx)
	}
	if err != nil {
		return nil, err
	}
	return encryptedConn, nil
}

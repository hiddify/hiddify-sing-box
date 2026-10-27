package v2rayhttpupgrade

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type hAcceptHandler struct {
	conns chan net.Conn
}

func (h *hAcceptHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.conns <- conn
}

// Xray clients send Sec-WebSocket-Key on HTTPUpgrade; the server must upgrade, not answer 404.
func TestH_ServerAcceptsSecWebSocketKey(t *testing.T) {
	handler := &hAcceptHandler{conns: make(chan net.Conn, 1)}
	server, err := NewServer(context.Background(), logger.NOP(), option.V2RayHTTPUpgradeOptions{Path: "/up"}, nil, handler)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go server.Serve(listener)
	defer server.Close()

	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	request, err := http.NewRequest(http.MethodGet, "http://"+listener.Addr().String()+"/up", nil)
	require.NoError(t, err)
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	request.Header.Set("Sec-WebSocket-Version", "13")
	require.NoError(t, request.Write(conn))

	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, response.StatusCode)
	require.Equal(t, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", response.Header.Get("Sec-WebSocket-Accept"))

	select {
	case serverConn := <-handler.conns:
		serverConn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("connection not handed to the handler")
	}
}

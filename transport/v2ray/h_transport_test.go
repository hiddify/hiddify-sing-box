package v2ray

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayhttp"
	"github.com/sagernet/sing-box/transport/v2rayhttpupgrade"
	"github.com/sagernet/sing-box/transport/v2rayraw"
	"github.com/sagernet/sing-box/transport/v2raywebsocket"
	xhttp "github.com/sagernet/sing-box/transport/v2rayxhttp"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type hEchoHandler struct{}

func (h *hEchoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	io.Copy(conn, conn)
}

var hServerAddr = M.ParseSocksaddr("127.0.0.1:8443")

func TestH_ClientTransportDispatch(t *testing.T) {
	cases := []struct {
		options  option.V2RayTransportOptions
		expected any
	}{
		{option.V2RayTransportOptions{Type: C.V2RayTransportTypeHTTP}, &v2rayhttp.Client{}},
		{option.V2RayTransportOptions{Type: C.V2RayTransportTypeWebsocket}, &v2raywebsocket.Client{}},
		{option.V2RayTransportOptions{Type: C.V2RayTransportTypeHTTPUpgrade}, &v2rayhttpupgrade.Client{}},
		{option.V2RayTransportOptions{Type: C.V2RayTransportTypeXHTTP, XHTTPOptions: option.V2RayXHTTPOptions{Mode: "packet-up"}}, &xhttp.Client{}},
		{option.V2RayTransportOptions{Type: C.V2RayTransportTypeRaw}, &v2rayraw.Client{}},
	}
	for _, testCase := range cases {
		t.Run(testCase.options.Type, func(t *testing.T) {
			transport, err := NewClientTransport(context.Background(), N.SystemDialer, hServerAddr, testCase.options, nil)
			require.NoError(t, err)
			require.IsType(t, testCase.expected, transport)
			require.NoError(t, transport.Close())
		})
	}
}

func TestH_ClientTransportDispatchErrors(t *testing.T) {
	transport, err := NewClientTransport(context.Background(), N.SystemDialer, hServerAddr, option.V2RayTransportOptions{}, nil)
	require.NoError(t, err)
	require.Nil(t, transport)

	_, err = NewClientTransport(context.Background(), N.SystemDialer, hServerAddr, option.V2RayTransportOptions{Type: "bogus"}, nil)
	require.EqualError(t, err, "unknown client transport type: bogus")

	_, err = NewClientTransport(context.Background(), N.SystemDialer, hServerAddr, option.V2RayTransportOptions{Type: C.V2RayTransportTypeQUIC}, nil)
	require.ErrorIs(t, err, C.ErrTLSRequired)

	transport, err = NewClientTransport(context.Background(), N.SystemDialer, hServerAddr, option.V2RayTransportOptions{Type: C.V2RayTransportTypeXHTTP}, nil)
	require.Error(t, err)
	require.Nil(t, transport)
}

func TestH_ServerTransportDispatch(t *testing.T) {
	cases := []struct {
		options  option.V2RayTransportOptions
		expected any
	}{
		{option.V2RayTransportOptions{Type: C.V2RayTransportTypeHTTP}, &v2rayhttp.Server{}},
		{option.V2RayTransportOptions{Type: C.V2RayTransportTypeWebsocket}, &v2raywebsocket.Server{}},
		{option.V2RayTransportOptions{Type: C.V2RayTransportTypeHTTPUpgrade}, &v2rayhttpupgrade.Server{}},
		{option.V2RayTransportOptions{Type: C.V2RayTransportTypeXHTTP, XHTTPOptions: option.V2RayXHTTPOptions{Mode: "auto"}}, &xhttp.Server{}},
		{option.V2RayTransportOptions{Type: C.V2RayTransportTypeRaw}, &v2rayraw.Server{}},
	}
	for _, testCase := range cases {
		t.Run(testCase.options.Type, func(t *testing.T) {
			transport, err := NewServerTransport(context.Background(), logger.NOP(), testCase.options, nil, &hEchoHandler{})
			require.NoError(t, err)
			require.IsType(t, testCase.expected, transport)
			require.Equal(t, []string{N.NetworkTCP}, transport.Network())
			require.NoError(t, transport.Close())
		})
	}
}

func TestH_ServerTransportDispatchErrors(t *testing.T) {
	transport, err := NewServerTransport(context.Background(), logger.NOP(), option.V2RayTransportOptions{}, nil, &hEchoHandler{})
	require.NoError(t, err)
	require.Nil(t, transport)

	_, err = NewServerTransport(context.Background(), logger.NOP(), option.V2RayTransportOptions{Type: "bogus"}, nil, &hEchoHandler{})
	require.EqualError(t, err, "unknown transport type: bogus")

	_, err = NewServerTransport(context.Background(), logger.NOP(), option.V2RayTransportOptions{Type: C.V2RayTransportTypeQUIC}, nil, &hEchoHandler{})
	require.ErrorIs(t, err, C.ErrTLSRequired)
}

func TestH_RawThroughDispatcher(t *testing.T) {
	options := option.V2RayTransportOptions{Type: C.V2RayTransportTypeRaw}
	server, err := NewServerTransport(context.Background(), logger.NOP(), options, nil, &hEchoHandler{})
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go server.Serve(listener)
	defer func() {
		listener.Close()
		server.Close()
	}()
	client, err := NewClientTransport(context.Background(), N.SystemDialer, M.SocksaddrFromNet(listener.Addr()), options, nil)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	require.NoError(t, err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write([]byte("dispatch"))
	require.NoError(t, err)
	reply := make([]byte, 8)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, "dispatch", string(reply))
}

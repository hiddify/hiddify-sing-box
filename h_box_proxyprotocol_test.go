package box_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/require"
)

// client --PROXY(192.0.2.10)--> mixed inbound (proxy_protocol) --> direct (proxy_protocol 2) --> server
func TestH_ProxyProtocolInboundAndDirectOutbound(t *testing.T) {
	// the destination reads the PROXY header the direct outbound sends
	server, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()
	headers := make(chan *proxyproto.Header, 1)
	go func() {
		conn, err := server.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		header, err := proxyproto.Read(reader)
		if err != nil {
			headers <- nil
			return
		}
		headers <- header
		line, _ := reader.ReadString('\n')
		conn.Write([]byte(line))
	}()

	inboundPort := hFreeTCPPort(t)
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
		"log": {"disabled": true},
		"inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(inboundPort)+`, "proxy_protocol": true}],
		"outbounds": [{"type": "direct", "tag": "direct", "proxy_protocol": 2}],
		"route": {"rules": [
			{"source_ip_cidr": ["192.0.2.10/32"], "outbound": "direct"},
			{"action": "reject"}
		]}
	}`))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	defer instance.Close()
	require.NoError(t, instance.Start())

	connect := func(source string) (net.Conn, *http.Response, error) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(inboundPort), 2*time.Second)
		if err != nil {
			return nil, nil, err
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		header := proxyproto.HeaderProxyFromAddrs(1, &net.TCPAddr{IP: net.ParseIP(source), Port: 40000}, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: inboundPort})
		if _, err = header.WriteTo(conn); err != nil {
			return conn, nil, err
		}
		target := server.Addr().String()
		if _, err = conn.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n")); err != nil {
			return conn, nil, err
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		return conn, response, err
	}

	// the inbound took the client address from the PROXY header: the source rule matches
	conn, response, err := connect("192.0.2.10")
	require.NoError(t, err)
	defer conn.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	_, err = conn.Write([]byte("ping\n"))
	require.NoError(t, err)
	echo := make([]byte, 5)
	_, err = io.ReadFull(conn, echo)
	require.NoError(t, err)
	require.Equal(t, "ping\n", string(echo))

	// the direct outbound passed the original client on in a v2 header
	select {
	case header := <-headers:
		require.NotNil(t, header, "no PROXY header from the direct outbound")
		require.Equal(t, byte(2), header.Version)
		require.Equal(t, "192.0.2.10", header.SourceAddr.(*net.TCPAddr).IP.String())
		require.Equal(t, server.Addr().String(), header.DestinationAddr.String())
	case <-time.After(3 * time.Second):
		t.Fatal("the server got no connection")
	}

	// another claimed source does not match the rule and is rejected (the HTTP inbound answers
	// 200 before routing, so the rejection shows as the connection closing without an echo)
	conn2, _, err := connect("192.0.2.99")
	if conn2 != nil {
		defer conn2.Close()
	}
	if err == nil {
		_, _ = conn2.Write([]byte("ping\n"))
		_, err = io.ReadFull(conn2, make([]byte, 5))
	}
	require.Error(t, err, "a non-matching source was let through")
}

func TestH_DirectOutboundRejectsBadProxyProtocolVersion(t *testing.T) {
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{"outbounds": [{"type": "direct", "tag": "d", "proxy_protocol": 3}]}`))
	require.NoError(t, err)
	_, err = box.New(box.Options{Context: ctx, Options: options})
	require.ErrorContains(t, err, "invalid proxy protocol version: 3")
}

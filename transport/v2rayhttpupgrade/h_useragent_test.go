package v2rayhttpupgrade

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func hCaptureUserAgent(t *testing.T, headers badoption.HTTPHeader) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	userAgent := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			userAgent <- "<error: " + err.Error() + ">"
			return
		}
		userAgent <- request.Header.Get("User-Agent")
	}()
	client, err := NewClient(context.Background(), N.SystemDialer, M.SocksaddrFromNet(listener.Addr()), option.V2RayHTTPUpgradeOptions{Path: "/up", Headers: headers}, nil)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	if err == nil {
		conn.Write([]byte("x"))
		conn.Close()
	}
	select {
	case value := <-userAgent:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("no request received")
		return ""
	}
}

func TestH_DefaultBrowserUserAgent(t *testing.T) {
	require.Equal(t, C.DefaultBrowserAgent, hCaptureUserAgent(t, nil))
}

func TestH_CustomUserAgentPreserved(t *testing.T) {
	require.Equal(t, "custom-agent/1.0", hCaptureUserAgent(t, badoption.HTTPHeader{"User-Agent": {"custom-agent/1.0"}}))
}

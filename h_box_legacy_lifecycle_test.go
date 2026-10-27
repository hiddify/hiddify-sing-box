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

	"github.com/stretchr/testify/require"
)

// Outbounds that still use Start/PostStart (balancer, psiphon, dnstt, gooserelay) must be
// started by the box; a balancer that was never started has no strategy and cannot route.
func TestH_LegacyLifecycleOutboundIsStarted(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	for _, strategy := range []string{"round-robin", "lowest-delay", "consistent-hashing", "sticky-sessions"} {
		t.Run(strategy, func(t *testing.T) {
			mixedPort := hFreeTCPPort(t)
			ctx := include.Context(context.Background())
			options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
				"log": {"disabled": true},
				"inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(mixedPort)+`}],
				"outbounds": [
					{"type": "balancer", "tag": "balance", "outbounds": ["d1", "d2"], "strategy": "`+strategy+`"},
					{"type": "direct", "tag": "d1"},
					{"type": "direct", "tag": "d2"}
				],
				"route": {"final": "balance"}
			}`))
			require.NoError(t, err)
			instance, err := box.New(box.Options{Context: ctx, Options: options})
			require.NoError(t, err)
			defer instance.Close()
			require.NoError(t, instance.Start())

			conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(mixedPort), 2*time.Second)
			require.NoError(t, err)
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			target := echo.Addr().String()
			_, err = conn.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))
			require.NoError(t, err)
			reader := bufio.NewReader(conn)
			response, err := http.ReadResponse(reader, nil)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, response.StatusCode)
			_, err = conn.Write([]byte("ping"))
			require.NoError(t, err)
			reply := make([]byte, 4)
			_, err = io.ReadFull(reader, reply)
			require.NoError(t, err, "nothing came back through the balancer")
			require.Equal(t, "ping", string(reply))
		})
	}
}

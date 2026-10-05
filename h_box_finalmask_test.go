package box_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// An outbound with final_mask dials through the Xray masks: the first packet reaches the server
// in fragments and the connection still works end to end.
func TestH_OutboundFinalMask(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	reads := make(chan int, 64)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				close(reads)
				return
			}
			reads <- n
			conn.Write(buf[:n])
		}
	}()

	config := `{
		"log": {"disabled": true},
		"outbounds": [{
			"type": "direct",
			"tag": "masked",
			"final_mask": {"tcp": [{"type": "fragment", "settings": {"packets": "1-1", "length": "2-4", "delay": "5"}}]}
		}]
	}`
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	defer instance.Close()
	require.NoError(t, instance.Start())

	outbound, loaded := instance.Outbound().Outbound("masked")
	require.True(t, loaded)
	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := outbound.DialContext(dialCtx, N.NetworkTCP, M.SocksaddrFromNet(listener.Addr()))
	require.NoError(t, err)
	defer conn.Close()

	payload := []byte("0123456789abcdef")
	_, err = conn.Write(payload)
	require.NoError(t, err)
	got := make([]byte, len(payload))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	require.Equal(t, payload, got)
	require.LessOrEqual(t, <-reads, 4, "the first packet must arrive fragmented")
}

func TestH_OutboundFinalMaskInvalid(t *testing.T) {
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{"outbounds":[{"type":"direct","tag":"d","final_mask":{"tcp":[{"type":"noise"}]}}]}`))
	require.NoError(t, err)
	_, err = box.New(box.Options{Context: ctx, Options: options})
	require.ErrorContains(t, err, "final_mask.tcp[0]")
}

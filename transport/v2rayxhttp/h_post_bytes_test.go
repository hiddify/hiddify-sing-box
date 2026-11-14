package xhttp

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/xray/buf"
	Xbadoption "github.com/sagernet/sing-box/common/xray/json/badoption"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// A server whose sc_max_each_post_bytes is not bigger than one buffer panicked at the first
// dial and took the app down (hiddify-app#2554); the range is raised and the server works.
func TestH_XHTTPSmallScMaxEachPostBytes(t *testing.T) {
	for _, value := range []string{"4096-4096", "1536-6144", "4096-16384", "8192"} {
		t.Run(value, func(t *testing.T) {
			server := hOptions(t, `{"mode":"packet-up","path":"/xh"}`)
			client := hOptions(t, `{"mode":"packet-up","path":"/xh","sc_max_each_post_bytes":"`+value+`"}`)
			addr := hStartServer(t, server, nil)
			transport, err := NewClient(context.Background(), N.SystemDialer, addr, client, nil)
			require.NoError(t, err)
			defer transport.Close()

			conn, err := transport.DialContext(context.Background())
			require.NoError(t, err)
			defer conn.Close()

			payload := bytes.Repeat([]byte("hiddify!"), 4096) // 32 KB, several posts
			_, err = conn.Write(payload)
			require.NoError(t, err)
			received := make([]byte, len(payload))
			readErr := make(chan error, 1)
			go func() {
				_, err := io.ReadFull(conn, received)
				readErr <- err
			}()
			select {
			case err = <-readErr:
			case <-time.After(5 * time.Second):
				t.Fatal("no echo")
			}
			require.NoError(t, err)
			require.True(t, bytes.Equal(payload, received))
		})
	}
}

func TestH_MinScMaxEachPostBytes(t *testing.T) {
	for _, testCase := range []struct{ in, out Xbadoption.Range }{
		{Xbadoption.Range{From: 4096, To: 4096}, Xbadoption.Range{From: buf.Size + 1, To: buf.Size + 1}},
		{Xbadoption.Range{From: 4096, To: 16384}, Xbadoption.Range{From: buf.Size + 1, To: 16384}},
		{Xbadoption.Range{From: buf.Size, To: buf.Size}, Xbadoption.Range{From: buf.Size + 1, To: buf.Size + 1}},
		{Xbadoption.Range{From: 1000000, To: 1000000}, Xbadoption.Range{From: 1000000, To: 1000000}},
	} {
		require.Equal(t, testCase.out, hMinScMaxEachPostBytes(testCase.in))
	}
}

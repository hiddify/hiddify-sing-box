package xhttp

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/xray/buf"
	Xbadoption "github.com/sagernet/sing-box/common/xray/json/badoption"
	"github.com/sagernet/sing-box/common/xray/pipe"
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
		{Xbadoption.Range{From: 4096, To: 4096}, Xbadoption.Range{From: 4096, To: 4096}},
		{Xbadoption.Range{From: 0, To: 16384}, Xbadoption.Range{From: 1, To: 16384}},
		{Xbadoption.Range{From: 0, To: 0}, Xbadoption.Range{From: 1, To: 1}},
		{Xbadoption.Range{From: 1000000, To: 1000000}, Xbadoption.Range{From: 1000000, To: 1000000}},
	} {
		require.Equal(t, testCase.out, hMinScMaxEachPostBytes(testCase.in))
	}
}

// A server that sets a small sc_max_each_post_bytes refuses a bigger post with 413. The client
// raised a value of up to 8192 bytes to a little more, so every connection to such a server
// failed at its first full post; it keeps to the value.
func TestH_XHTTPHonoursASmallScMaxEachPostBytes(t *testing.T) {
	for _, value := range []string{"4096-4096", "1536-6144", "8192", "300"} {
		t.Run(value, func(t *testing.T) {
			options := `{"mode":"packet-up","path":"/xh","sc_max_each_post_bytes":"` + value + `"}`
			addr := hStartServer(t, hOptions(t, options), nil) // the server enforces the same limit
			transport, err := NewClient(context.Background(), N.SystemDialer, addr, hOptions(t, options), nil)
			require.NoError(t, err)
			defer transport.Close()

			conn, err := transport.DialContext(context.Background())
			require.NoError(t, err)
			defer conn.Close()

			payload := bytes.Repeat([]byte("hiddify!"), 4096) // 32 KB: many posts, written at once
			received := make([]byte, len(payload))
			readErr := make(chan error, 1)
			go func() {
				_, err := io.ReadFull(conn, received)
				readErr <- err
			}()
			_, err = conn.Write(payload)
			require.NoError(t, err)
			select {
			case err = <-readErr:
			case <-time.After(10 * time.Second):
				t.Fatal("no echo: the server refused a post")
			}
			require.NoError(t, err)
			require.True(t, bytes.Equal(payload, received))
		})
	}
}

// The pieces the upload writer puts into the pipe are never bigger than the post.
func TestH_UploadWriterPiecesFitThePost(t *testing.T) {
	for _, limit := range []int32{300, 4096, buf.Size, buf.Size * 3} {
		reader, writer := pipe.New(pipe.WithSizeLimit(limit - hUploadPiece(limit)))
		upload := uploadWriter{writer, limit}
		payload := bytes.Repeat([]byte("z"), buf.Size*4+17)
		go func() {
			upload.Write(payload)
			writer.Close()
		}()
		var total int
		for {
			chunk, err := reader.ReadMultiBuffer()
			if err != nil {
				break
			}
			require.LessOrEqual(t, chunk.Len(), limit, "a post bigger than sc_max_each_post_bytes")
			total += int(chunk.Len())
			buf.ReleaseMulti(chunk)
		}
		require.Equal(t, len(payload), total)
	}
}

// A request that cannot be written is an error of the upload, over HTTP/1.1 too: there it was a
// panic, which takes the whole app down.
func TestH_XHTTPPostPacketWriteErrorIsAnError(t *testing.T) {
	client := hDialerClient(t, "1.1")
	require.NotPanics(t, func() {
		// a body shorter than the length it was announced with cannot be written
		err := client.PostPacket(context.Background(), "http://127.0.0.1:1/xh/session/0", "session", "0", strings.NewReader("data"), 10)
		require.ErrorContains(t, err, "ContentLength")
	})
}

//go:build with_xdrive

package box_test

import (
	"context"
	"io"
	"net"
	"os"
	"strings"
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

// A VLESS client and server over the xdrive transport meet only in a shared folder (XDRIVE's
// "local" service): the client announces a session there and the server picks it up.
func TestH_XDriveLocalRoundTrip(t *testing.T) {
	echo := startEchoServer(t)
	folder := xdriveFolder(t)
	transport := `{"type": "xdrive", "service": "local", "remote_folder": "` + folder + `", "poll_interval_ms": 20, "flush_interval_ms": 5}`
	config := `{
		"log": {"level": "warn"},
		"inbounds": [{
			"type": "vless", "tag": "in", "listen": "127.0.0.1", "listen_port": 0,
			"users": [{"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
			"transport": ` + transport + `
		}],
		"outbounds": [
			{"type": "direct", "tag": "direct"},
			{
				"type": "vless", "tag": "xdrive", "server": "127.0.0.1", "server_port": 1,
				"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
				"transport": ` + transport + `
			}
		]
	}`
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	defer instance.Close()
	require.NoError(t, instance.Start())

	outbound, loaded := instance.Outbound().Outbound("xdrive")
	require.True(t, loaded)
	dialCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := outbound.DialContext(dialCtx, N.NetworkTCP, M.SocksaddrFromNet(echo.Addr()))
	require.NoError(t, err)
	defer conn.Close()

	for _, payload := range [][]byte{[]byte("hello over xdrive"), []byte(strings.Repeat("0123456789", 30000))} {
		_, err = conn.Write(payload)
		require.NoError(t, err)
		got := make([]byte, len(payload))
		conn.SetReadDeadline(time.Now().Add(20 * time.Second))
		_, err = io.ReadFull(conn, got)
		require.NoError(t, err)
		require.Equal(t, payload, got)
	}
}

// xdriveFolder is a storage folder for one test. Closing the boxes only cancels the xdrive
// sessions: their storage goroutines (the watermark acknowledgement among them) still put a file or
// two in the folder for a moment, so t.TempDir's one removal could find it not empty and fail the
// test; this one waits for the storage to go quiet.
func xdriveFolder(t *testing.T) string {
	folder, err := os.MkdirTemp("", "xdrive")
	require.NoError(t, err)
	t.Cleanup(func() {
		deadline := time.Now().Add(10 * time.Second)
		for {
			err := os.RemoveAll(folder)
			if err == nil || time.Now().After(deadline) {
				require.NoError(t, err)
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
	return folder
}

func TestH_XDriveOptions(t *testing.T) {
	ctx := include.Context(context.Background())
	for _, test := range []struct {
		transport string
		err       string
	}{
		{`{"type": "xdrive", "service": "google-drive", "remote_folder": "x", "secrets": ["id", "secret", "token"]}`, ""},
		{`{"type": "xdrive", "service": "google-drive", "secrets": ["id"]}`, "3 secrets"},
		{`{"type": "xdrive", "service": "s3", "remote_folder": "x", "s3": {"endpoint": "https://s3.example.com", "region": "us-east-1", "bucket": "b"}, "secrets": ["key", "secret"]}`, ""},
		{`{"type": "xdrive", "service": "s3"}`, `"s3" object`},
		{`{"type": "xdrive", "service": "dropbox"}`, "unknown"},
		{`{"type": "xdrive"}`, "missing"},
	} {
		config := `{"log": {"disabled": true}, "outbounds": [{"type": "vless", "tag": "x", "server": "127.0.0.1", "server_port": 1, "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "transport": ` + test.transport + `}]}`
		options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
		require.NoError(t, err, test.transport)
		instance, err := box.New(box.Options{Context: ctx, Options: options})
		if test.err == "" {
			require.NoError(t, err, test.transport)
			instance.Close()
		} else {
			require.ErrorContains(t, err, test.err, test.transport)
		}
	}
}

func startEchoServer(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return listener
}

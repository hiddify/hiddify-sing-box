package box_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
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

// hTLSRecords reads TLS records from conn until the first handshake message is complete and
// returns the length of each record that carried it.
func hTLSRecords(conn net.Conn) ([]int, error) {
	var (
		lengths   []int
		handshake []byte
	)
	for {
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			return lengths, err
		}
		body := make([]byte, binary.BigEndian.Uint16(header[3:]))
		if _, err := io.ReadFull(conn, body); err != nil {
			return lengths, err
		}
		if header[0] != 22 {
			continue
		}
		lengths = append(lengths, len(body))
		handshake = append(handshake, body...)
		if len(handshake) >= 4 && len(handshake) >= 4+int(handshake[1])<<16|int(handshake[2])<<8|int(handshake[3]) {
			return lengths, nil
		}
	}
}

// The legacy dialer tls_fragment is applied as a finalmask fragment mask (packets "tlshello"):
// the ClientHello goes out as several TLS records of at most "size" bytes.
func TestH_TLSFragmentUsesFinalMask(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	records := make(chan []int, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		lengths, _ := hTLSRecords(conn)
		records <- lengths
	}()
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
		"log": {"disabled": true},
		"outbounds": [{"type": "vless", "tag": "fragmented", "server": "127.0.0.1",
			"server_port": `+strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)+`,
			"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
			"tls_fragment": {"enabled": true, "size": "20-40", "sleep": "0"},
			"tls": {"enabled": true, "server_name": "example.com"}}]
	}`))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	defer instance.Close()
	require.NoError(t, instance.Start())
	outbound, _ := instance.Outbound().Outbound("fragmented")
	go func() {
		dialCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err := outbound.DialContext(dialCtx, N.NetworkTCP, M.ParseSocksaddr("example.com:80"))
		if err == nil {
			conn.Close()
		}
	}()
	select {
	case lengths := <-records:
		require.Greater(t, len(lengths), 1, "the ClientHello must be split into TLS records")
		for _, length := range lengths {
			require.LessOrEqual(t, length, 40)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no ClientHello")
	}
}

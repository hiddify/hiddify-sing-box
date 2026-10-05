package finalmask

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// the fm= value of a subscription link, URL-decoded
const fragmentFinalMask = `{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"1-104","delay":"0","maxSplit":"0"}},{"type":"fragment","settings":{"packets":"1-1","length":"1-114","delay":"1","maxSplit":"11"}}]}`

func parseOptions(t *testing.T, content string) *option.FinalMaskOptions {
	t.Helper()
	var options option.FinalMaskOptions
	require.NoError(t, json.Unmarshal([]byte(content), &options))
	return &options
}

func TestBuildFragmentFinalMask(t *testing.T) {
	masks, err := Build(parseOptions(t, fragmentFinalMask))
	require.NoError(t, err)
	require.NotNil(t, masks.TCP)
	require.Nil(t, masks.UDP)
}

func TestBuildEmpty(t *testing.T) {
	masks, err := Build(nil)
	require.NoError(t, err)
	require.Nil(t, masks)
	masks, err = Build(&option.FinalMaskOptions{})
	require.NoError(t, err)
	require.Nil(t, masks)
}

func TestBuildAllMaskTypes(t *testing.T) {
	for _, content := range []string{
		`{"tcp":[{"type":"fragment","settings":{"packets":"1-3","lengths":["5-10","20"],"delays":["1-2"]}}]}`,
		`{"tcp":[{"type":"header-custom","settings":{"clients":[[{"type":"str","packet":"GET / HTTP/1.1\r\n\r\n"}]],"servers":[[{"rand":16}]]}}]}`,
		`{"tcp":[{"type":"sudoku","settings":{"password":"p","ascii":"prefer_entropy","paddingMin":1,"paddingMax":10}}]}`,
		`{"udp":[{"type":"noise","settings":{"reset":"10-20","noise":[{"rand":"10-20","delay":"5"},{"type":"hex","packet":"deadbeef"}]}}]}`,
		`{"udp":[{"type":"header-custom","settings":{"mode":"standalone","client":[{"type":"base64","packet":"AAEC"}]}}]}`,
		`{"udp":[{"type":"mkcp-legacy","settings":{"header":"wechat"}},{"type":"mkcp-legacy","settings":{"value":"seed"}}]}`,
		`{"udp":[{"type":"salamander","settings":{"password":"p"}},{"type":"salamander","settings":{"password":"p","packetSize":"100-1200"}}]}`,
		`{"udp":[{"type":"sudoku","settings":{"password":"p"}}]}`,
		`{"udp":[{"type":"xdns","settings":{"resolvers":["example.com+udp://8.8.8.8:53"]}}]}`,
		`{"udp":[{"type":"xicmp","settings":{"ips":["1.1.1.1"]}}]}`,
		`{"udp":[{"type":"realm","settings":{"url":"realm://token@realm.example.com/room","stunServers":["stun.example.com:3478"],"tlsConfig":{"serverName":"realm.example.com","alpn":["h2"]}}}]}`,
		`{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"10-20"}}],"udp":[{"type":"noise","settings":{"noise":[{"rand":5}]}}],"quicParams":{"congestion":"bbr"}}`,
	} {
		masks, err := Build(parseOptions(t, content))
		require.NoError(t, err, content)
		require.NotNil(t, masks, content)
	}
}

func TestBuildRejectsInvalid(t *testing.T) {
	for _, content := range []string{
		`{"tcp":[{"type":"unknown"}]}`,
		`{"tcp":[{"type":"noise"}]}`,    // udp only
		`{"udp":[{"type":"fragment"}]}`, // tcp only
		`{"tcp":[{"type":"fragment","settings":{"packets":"0-3","length":"1-10"}}]}`,
		`{"tcp":[{"type":"fragment","settings":{"packets":"tlshello"}}]}`, // length min 0
		`{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"a-b"}}]}`,
		`{"udp":[{"type":"xdns","settings":{}}]}`,
	} {
		_, err := Build(parseOptions(t, content))
		require.Error(t, err, content)
	}
}

type recordConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (c *recordConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	c.mu.Unlock()
	return len(p), nil
}

func TestFragmentSplitsFirstPacket(t *testing.T) {
	masks, err := Build(parseOptions(t, `{"tcp":[{"type":"fragment","settings":{"packets":"1-1","length":"3-5","delay":"0"}}]}`))
	require.NoError(t, err)
	client, server := net.Pipe()
	defer server.Close()
	raw := &recordConn{Conn: client}
	conn, err := masks.TCP.WrapConnClient(raw)
	require.NoError(t, err)
	payload := bytes.Repeat([]byte("0123456789"), 5)
	n, err := conn.Write(payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)
	require.Greater(t, len(raw.writes), 1, "first packet must be split")
	require.Equal(t, payload, bytes.Join(raw.writes, nil))
	for _, w := range raw.writes[:len(raw.writes)-1] {
		require.LessOrEqual(t, len(w), 5)
	}
	// only packet 1 is fragmented
	_, err = conn.Write(payload)
	require.NoError(t, err)
	require.Equal(t, payload, raw.writes[len(raw.writes)-1])
}

func TestFragmentTLSHello(t *testing.T) {
	masks, err := Build(parseOptions(t, fragmentFinalMask))
	require.NoError(t, err)
	client, server := net.Pipe()
	defer server.Close()
	raw := &recordConn{Conn: client}
	conn, err := masks.TCP.WrapConnClient(raw)
	require.NoError(t, err)
	body := bytes.Repeat([]byte{1}, 300)
	hello := append([]byte{22, 3, 1, byte(len(body) >> 8), byte(len(body))}, body...)
	_, err = conn.Write(hello)
	require.NoError(t, err)
	require.Greater(t, len(raw.writes), 1, "client hello must be fragmented")
}

func TestWrapConnTCPRoundTrip(t *testing.T) {
	options := parseOptions(t, `{"tcp":[{"type":"fragment","settings":{"packets":"1-2","length":"1-3","delay":"0-1"}}]}`)
	masks, err := Build(options)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			conn.Write(buf[:n])
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dial(ctx, masks, N.NetworkTCP, M.SocksaddrFromNet(listener.Addr()))
	require.NoError(t, err)
	defer conn.Close()
	payload := []byte("hello final mask over tcp")
	_, err = conn.Write(payload)
	require.NoError(t, err)
	got := make([]byte, len(payload))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = readFull(conn, got)
	require.NoError(t, err)
	require.Equal(t, payload, got)
}

func dial(ctx context.Context, masks *Masks, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := N.SystemDialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return masks.WrapConn(conn, network, destination)
}

func readFull(conn net.Conn, p []byte) (int, error) {
	total := 0
	for total < len(p) {
		n, err := conn.Read(p[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// the client masks through the sing-box dialer, the server unmasks with Xray's own manager
func TestWrapUDPSalamanderRoundTrip(t *testing.T) {
	const content = `{"udp":[{"type":"salamander","settings":{"password":"secret"}},{"type":"noise","settings":{"noise":[{"rand":"10-20"}]}}]}`
	clientMasks, err := Build(parseOptions(t, content))
	require.NoError(t, err)
	serverMasks, err := Build(parseOptions(t, `{"udp":[{"type":"salamander","settings":{"password":"secret"}}]}`))
	require.NoError(t, err)

	rawServer, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer rawServer.Close()
	server, err := serverMasks.UDP.WrapPacketConnServer(rawServer)
	require.NoError(t, err)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			server.WriteTo(buf[:n], addr)
		}
	}()

	destination := M.SocksaddrFromNet(rawServer.LocalAddr())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	payload := []byte("hello final mask over udp")
	packetConn, err := N.SystemDialer.ListenPacket(ctx, destination)
	require.NoError(t, err)
	packetConn, err = clientMasks.WrapPacketConn(packetConn)
	require.NoError(t, err)
	defer packetConn.Close()
	packetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 2048)
	for {
		_, err = packetConn.WriteTo(payload, destination.UDPAddr())
		require.NoError(t, err)
		n, _, err := packetConn.ReadFrom(got)
		require.NoError(t, err)
		// salamander is unauthenticated: the server also echoes the noise packets, as garbage
		if n == len(payload) {
			require.Equal(t, payload, got[:n])
			break
		}
	}

	conn, err := dial(ctx, clientMasks, N.NetworkUDP, destination)
	require.NoError(t, err)
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		_, err = conn.Write(payload)
		require.NoError(t, err)
		n, err := conn.Read(got)
		require.NoError(t, err)
		if n == len(payload) {
			require.Equal(t, payload, got[:n])
			break
		}
	}
}

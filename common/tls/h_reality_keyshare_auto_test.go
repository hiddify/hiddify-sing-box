//go:build with_utls

package tls

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// hReport reports a handshake with the key share the state picks now.
func hReport(auto *realityKeyShareAuto, err error) {
	ctx := context.Background()
	auto.report(ctx, ctx, nil, auto.useClassical(ctx), err)
}

func TestH_RealityKeyShareAutoTestsOnce(t *testing.T) {
	ctx := context.Background()
	auto := &realityKeyShareAuto{}
	require.False(t, auto.useClassical(ctx), "starts with hybrid")

	hReport(auto, io.EOF)
	require.False(t, auto.useClassical(ctx), "one failure does not start the test")
	hReport(auto, nil)
	hReport(auto, io.EOF)
	require.False(t, auto.useClassical(ctx), "a working handshake resets the count")
	hReport(auto, io.EOF)
	require.True(t, auto.useClassical(ctx), "two hybrid failures in a row start the test: classical")

	auto.report(ctx, ctx, nil, false, io.EOF)
	auto.report(ctx, ctx, nil, false, io.EOF)
	require.True(t, auto.useClassical(ctx), "handshakes started before the change are not counted")

	hReport(auto, io.EOF)
	hReport(auto, io.EOF)
	require.False(t, auto.useClassical(ctx), "classical fails too: settled on hybrid")
	for i := 0; i < 10; i++ {
		hReport(auto, io.EOF)
	}
	require.False(t, auto.useClassical(ctx), "hybrid settled after the test: classical is not tried again")
}

func TestH_RealityKeyShareAutoKeepsClassical(t *testing.T) {
	ctx := context.Background()
	auto := &realityKeyShareAuto{}
	hReport(auto, io.EOF)
	hReport(auto, io.EOF)
	hReport(auto, nil)
	require.True(t, auto.settled, "a working classical handshake settles it")
	hReport(auto, io.EOF)
	hReport(auto, nil)
	hReport(auto, io.EOF)
	require.True(t, auto.useClassical(ctx), "classical works: it stays")
	hReport(auto, errRealityVerificationFailed)
	hReport(auto, errRealityVerificationFailed)
	require.False(t, auto.useClassical(ctx), "the server now refuses classical (Xray v26.9.8+): back to hybrid")
	hReport(auto, io.EOF)
	hReport(auto, io.EOF)
	require.False(t, auto.useClassical(ctx), "and no second test")
}

// A man in the middle that answers with its own certificate makes REALITY verification fail. The
// hybrid ClientHello got through, so it must not start the test.
func TestH_RealityKeyShareAutoVerificationFailure(t *testing.T) {
	ctx := context.Background()
	auto := &realityKeyShareAuto{}
	for i := 0; i < 5; i++ {
		hReport(auto, errRealityVerificationFailed)
	}
	require.False(t, auto.useClassical(ctx), "verification failures do not start the test")
	require.False(t, auto.tested)
	hReport(auto, io.EOF)
	hReport(auto, errRealityVerificationFailed)
	hReport(auto, io.EOF)
	require.False(t, auto.useClassical(ctx), "an answer breaks a run of hybrid failures")
}

func TestH_RealityKeyShareAutoIgnoresCancel(t *testing.T) {
	auto := &realityKeyShareAuto{}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 5; i++ {
		auto.report(cancelled, cancelled, nil, false, context.Canceled)
	}
	require.False(t, auto.useClassical(context.Background()), "cancelled handshakes are not failures")
}

// The state belongs to the server, not to the outbound: a config built again (a subscription
// update, a reload) for the same server, under any tag, starts with what was learned.
func TestH_RealityKeyShareAutoPerServer(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	auto := realityKeyShareAutoFor("192.0.2.1:443", "www.example.com", key)
	require.Same(t, auto, realityKeyShareAutoFor("192.0.2.1:443", "www.example.com", key))
	require.NotSame(t, auto, realityKeyShareAutoFor("192.0.2.1:443", "www.example.org", key))
	require.NotSame(t, auto, realityKeyShareAutoFor("192.0.2.2:443", "www.example.com", key))
	require.NotSame(t, auto, realityKeyShareAutoFor("192.0.2.1:443", "www.example.com", []byte("another key")))
}

type hMemoryCacheFile struct {
	adapter.CacheFile
	saved map[string]*adapter.SavedBinary
}

func (c *hMemoryCacheFile) LoadBinary(tag string) *adapter.SavedBinary { return c.saved[tag] }

func (c *hMemoryCacheFile) SaveBinary(tag string, binary *adapter.SavedBinary) error {
	c.saved[tag] = binary
	return nil
}

// The settled key share is saved in the cache file, and a restarted core uses it without testing
// again; an entry older than the TTL is ignored.
func TestH_RealityKeyShareAutoCacheFile(t *testing.T) {
	cacheFile := &hMemoryCacheFile{saved: map[string]*adapter.SavedBinary{}}
	ctx := service.ContextWith[adapter.CacheFile](context.Background(), cacheFile)
	report := func(auto *realityKeyShareAuto, err error) {
		auto.report(ctx, ctx, nil, auto.useClassical(ctx), err)
	}

	auto := &realityKeyShareAuto{cacheTag: "test"}
	report(auto, nil)
	require.Empty(t, cacheFile.saved, "nothing is written while untested")
	report(auto, io.EOF)
	report(auto, io.EOF)
	report(auto, nil)
	require.Equal(t, "classical", string(cacheFile.saved["test"].Content))

	restarted := &realityKeyShareAuto{cacheTag: "test"}
	require.True(t, restarted.useClassical(ctx), "a restarted core starts with the saved classical")
	report(restarted, errRealityVerificationFailed)
	report(restarted, errRealityVerificationFailed)
	require.Equal(t, "hybrid", string(cacheFile.saved["test"].Content))

	again := &realityKeyShareAuto{cacheTag: "test"}
	report(again, io.EOF)
	report(again, io.EOF)
	require.False(t, again.useClassical(ctx), "a saved hybrid is not tested again after a restart")

	cacheFile.saved["old"] = &adapter.SavedBinary{Content: []byte("classical"), LastUpdated: time.Now().Add(-realityKeyShareCacheTTL - time.Hour)}
	require.False(t, (&realityKeyShareAuto{cacheTag: "old"}).useClassical(ctx), "an entry older than the TTL is ignored")
}

// hStartBigHelloDropper accepts TCP connections and forwards them to upstream, except those whose
// first TLS record (the ClientHello) is longer than 1200 bytes: those are closed, as networks that
// drop a ClientHello of two TCP segments do.
func hStartBigHelloDropper(t *testing.T, upstream string) string {
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
				header := make([]byte, 5)
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				length := int(binary.BigEndian.Uint16(header[3:]))
				if length > 1200 {
					return
				}
				server, err := net.Dial("tcp", upstream)
				if err != nil {
					return
				}
				defer server.Close()
				if _, err := server.Write(header); err != nil {
					return
				}
				go io.Copy(server, conn)
				io.Copy(conn, server)
			}()
		}
	}()
	return listener.Addr().String()
}

// hStartRealityServer starts a REALITY server that echoes 4 bytes, and returns its address.
func hStartRealityServer(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	dest := hStartTLSDest(t)
	destHost, destPort, err := net.SplitHostPort(dest)
	require.NoError(t, err)
	port, err := net.LookupPort("tcp", destPort)
	require.NoError(t, err)
	serverConfig, err := NewRealityServer(ctx, log.NewNOPFactory().Logger(), option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "www.example.com",
		Reality: &option.InboundRealityOptions{
			Enabled: true,
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{Server: destHost, ServerPort: uint16(port)},
			},
			ShortID:    []string{"0123456789abcdef"},
			PrivateKey: "UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc",
		},
	})
	require.NoError(t, err)
	serverConfig.(*RealityServerConfig).config.MinClientVer = []byte{26, 3, 27}
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
				tlsConn, err := ServerHandshake(ctx, conn, serverConfig)
				if err != nil {
					return
				}
				io.Copy(tlsConn, io.LimitReader(tlsConn, 4))
			}()
		}
	}()
	return listener.Addr().String()
}

func hNewRealityClient(t *testing.T, address string, fingerprint string, keyShare string) Config {
	t.Helper()
	config, err := NewRealityClient(context.Background(), logger.NOP(), address, option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "www.example.com",
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			ShortID:   "0123456789abcdef",
			PublicKey: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
			KeyShare:  keyShare,
		},
	})
	require.NoError(t, err)
	return config
}

// hRealityPing connects to address, makes the REALITY handshake and echoes 4 bytes.
func hRealityPing(t *testing.T, address string, config Config) error {
	t.Helper()
	rawConn, err := net.Dial("tcp", address)
	require.NoError(t, err)
	defer rawConn.Close()
	require.NoError(t, rawConn.SetDeadline(time.Now().Add(5*time.Second)))
	clientConn, err := ClientHandshake(context.Background(), rawConn, config)
	if err != nil {
		return err
	}
	defer clientConn.Close()
	if _, err := clientConn.Write([]byte("ping")); err != nil {
		return err
	}
	reply := make([]byte, 4)
	_, err = io.ReadFull(clientConn, reply)
	return err
}

// On a network that drops the hybrid ClientHello, a client with key_share "auto" connects after two
// failed handshakes, with the classical key share, and keeps it. Unset and "hybrid" behave as
// Chrome: hybrid every time, no fallback.
func TestH_RealityKeyShareAutoFallsBackToClassical(t *testing.T) {
	dropper := hStartBigHelloDropper(t, hStartRealityServer(t))

	auto := hNewRealityClient(t, dropper, "chrome", "auto")
	require.Error(t, hRealityPing(t, dropper, auto), "the hybrid ClientHello is dropped")
	require.Error(t, hRealityPing(t, dropper, auto.Clone()), "a clone shares what the client learned")
	for i := 0; i < 3; i++ {
		require.NoError(t, hRealityPing(t, dropper, auto), "classical after two failures, and it stays")
	}
	require.NoError(t, hRealityPing(t, dropper, hNewRealityClient(t, dropper, "chrome", "auto")),
		"a config built again for the server (a subscription update) starts with classical")

	for _, keyShare := range []string{"", "hybrid"} {
		client := hNewRealityClient(t, dropper, "chrome", keyShare)
		for i := 0; i < 3; i++ {
			require.Error(t, hRealityPing(t, dropper, client), "key_share %q never falls back", keyShare)
		}
	}
}

// The classical ClientHello of every fingerprint (an older browser's) passes REALITY, through a
// network that drops ClientHellos longer than one segment.
func TestH_RealityClassicalHandshake(t *testing.T) {
	dropper := hStartBigHelloDropper(t, hStartRealityServer(t))
	for _, fingerprint := range []string{"chrome", "firefox", "edge", "safari", "ios", "android", "360", "qq", "random", "randomized"} {
		require.NoError(t, hRealityPing(t, dropper, hNewRealityClient(t, dropper, fingerprint, "classical")), fingerprint)
	}
}

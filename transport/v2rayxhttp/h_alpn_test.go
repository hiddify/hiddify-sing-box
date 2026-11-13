package xhttp

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// hNewFingerprintTLSPair returns a server that offers serverALPN and a uTLS client with the
// fingerprint and clientALPN.
func hNewFingerprintTLSPair(t *testing.T, serverALPN []string, fingerprint string, clientALPN []string) (tls.ServerConfig, tls.Config) {
	t.Helper()
	keyPEM, certPEM, err := tls.GenerateCertificate(nil, nil, time.Now, "example.com", time.Now().Add(time.Hour))
	require.NoError(t, err)
	ctx := context.Background()
	serverConfig, err := tls.NewServer(ctx, logger.NOP(), option.InboundTLSOptions{
		Enabled:     true,
		ALPN:        serverALPN,
		Certificate: []string{string(certPEM)},
		Key:         []string{string(keyPEM)},
	})
	require.NoError(t, err)
	require.NoError(t, serverConfig.Start())
	t.Cleanup(func() { serverConfig.Close() })
	clientConfig, err := tls.NewClient(ctx, logger.NOP(), "example.com", option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  "example.com",
		ALPN:        clientALPN,
		Certificate: []string{string(certPEM)},
		UTLS:        &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint},
	})
	require.NoError(t, err)
	return serverConfig, clientConfig
}

// hNewClientHTTPVersion returns the HTTP version a client with tlsConfig and the download
// options in content speaks to the server and to the download server.
func hNewClientHTTPVersion(t *testing.T, content string, tlsConfig tls.Config) (string, string) {
	t.Helper()
	transport, err := NewClient(context.Background(), N.SystemDialer, M.ParseSocksaddr("127.0.0.1:443"), hOptions(t, content), tlsConfig)
	require.NoError(t, err)
	client := transport.(*Client)
	upload, _ := client.getHTTPClient()
	download, _ := client.getHTTPClient2()
	return upload.(*DefaultDialerClient).httpVersion, download.(*DefaultDialerClient).httpVersion
}

// hiddify-app#2542: a client with a uTLS fingerprint and no ALPN offered h2 in its hello (the
// browser's ALPN) but spoke HTTP/1.1, so a server that picked h2 (Xray, Cloudflare) failed it.
// Like Xray's client, a TLS client without ALPN offers h2 and http/1.1 and speaks HTTP/2.
func TestH_XHTTPDefaultALPN(t *testing.T) {
	content := `{"mode":"packet-up","path":"/xh","download":{"server":"127.0.0.2","server_port":443,"path":"/xh",` +
		`"tls":{"enabled":true,"server_name":"example.com","utls":{"enabled":true,"fingerprint":"chrome"}}}}`
	for _, fingerprint := range []string{"", "chrome"} {
		t.Run("fingerprint="+fingerprint, func(t *testing.T) {
			options := option.OutboundTLSOptions{Enabled: true, ServerName: "example.com"}
			if fingerprint != "" {
				options.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint}
			}
			clientTLS, err := tls.NewClient(context.Background(), logger.NOP(), "example.com", options)
			require.NoError(t, err)
			upload, download := hNewClientHTTPVersion(t, content, clientTLS)
			require.Equal(t, "2", upload)
			require.Equal(t, "2", download)
			require.Empty(t, clientTLS.NextProtos(), "the outbound's own TLS config is not changed")
		})
	}
	for alpn, version := range map[string]string{"http/1.1": "1.1", "h2": "2"} {
		t.Run("alpn="+alpn, func(t *testing.T) {
			clientTLS, err := tls.NewClient(context.Background(), logger.NOP(), "example.com", option.OutboundTLSOptions{
				Enabled: true, ServerName: "example.com", ALPN: []string{alpn},
				UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
			})
			require.NoError(t, err)
			upload, _ := hNewClientHTTPVersion(t, `{"mode":"packet-up","path":"/xh"}`, clientTLS)
			require.Equal(t, version, upload)
		})
	}
	upload, _ := hNewClientHTTPVersion(t, `{"mode":"packet-up","path":"/xh"}`, nil)
	require.Equal(t, "1.1", upload, "without TLS")
}

// The Hiddify server serves a fingerprinted client without ALPN in every mode.
func TestH_XHTTPFingerprintWithoutALPN(t *testing.T) {
	for _, mode := range []string{"stream-one", "stream-up", "packet-up"} {
		for _, fingerprint := range []string{"chrome", "firefox"} {
			t.Run(fmt.Sprintf("%s/%s", mode, fingerprint), func(t *testing.T) {
				serverTLS, clientTLS := hNewFingerprintTLSPair(t, []string{"h2", "http/1.1"}, fingerprint, nil)
				content := fmt.Sprintf(`{"mode":%q,"path":"/xh","x_padding_bytes":"100-1000"}`, mode)
				addr := hStartServer(t, hOptions(t, content), serverTLS)
				hRoundTrip(t, hOptions(t, content), clientTLS, addr, hPayloads(t, 1, 1500, 64*1024)...)
			})
		}
	}
}

// An explicit ALPN still decides the HTTP version.
func TestH_XHTTPFingerprintExplicitALPN(t *testing.T) {
	for _, alpn := range [][]string{{"http/1.1"}, {"h2"}} {
		t.Run(alpn[0], func(t *testing.T) {
			serverTLS, clientTLS := hNewFingerprintTLSPair(t, []string{"h2", "http/1.1"}, "chrome", alpn)
			content := `{"mode":"packet-up","path":"/xh","x_padding_bytes":"100-1000"}`
			addr := hStartServer(t, hOptions(t, content), serverTLS)
			hRoundTrip(t, hOptions(t, content), clientTLS, addr, hPayloads(t, 1, 5000)...)
		})
	}
}

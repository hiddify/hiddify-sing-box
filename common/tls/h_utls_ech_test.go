//go:build with_utls

package tls

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// TestH_UTLSECHEveryFingerprint dials an ECH server with each uTLS fingerprint. Fingerprints
// without an ECH extension (Safari, iOS, Edge, randomized, ...) failed with
// "tls: malformed outer client hello" (hiddify-app#2561).
func TestH_UTLSECHEveryFingerprint(t *testing.T) {
	keyPEM, certPEM, err := GenerateCertificate(nil, nil, time.Now, "example.org", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	echConfig, echKey, err := ECHKeygenDefault("cdn.example.net")
	if err != nil {
		t.Fatal(err)
	}
	logger := log.NewNOPFactory().Logger()
	server, err := NewServer(context.Background(), logger, option.InboundTLSOptions{
		Enabled: true, ServerName: "example.org",
		Certificate: []string{string(certPEM)}, Key: []string{string(keyPEM)},
		ECH: &option.InboundECHOptions{Enabled: true, Key: []string{echKey}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	fingerprints := []string{
		"chrome", "firefox", "edge", "safari", "ios", "android", "360", "qq", "random", "randomized",
		"hellochrome_120", "hellofirefox_148", "hellosafari_26_3", "helloios_14", "helloedge_106",
		"hellorandomizedalpn", "hellorandomizednoalpn", "hellogolang",
	}
	for _, fingerprint := range fingerprints {
		for _, padding := range []bool{false, true} {
			name := fingerprint
			options := option.OutboundTLSOptions{
				Enabled: true, ServerName: "example.org", Insecure: true,
				ALPN: []string{"h2", "http/1.1"},
				UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint},
				ECH:  &option.OutboundECHOptions{Enabled: true, Config: []string{echConfig}},
			}
			if padding {
				name += "+padding"
				options.TLSTricks = &option.TLSTricksOptions{PaddingMode: "random", PaddingSize: "100-200"}
			}
			t.Run(name, func(t *testing.T) {
				client, err := NewClient(context.Background(), logger, "example.org", options)
				if err != nil {
					if padding {
						t.Skip("no fixed spec for padding: ", err)
					}
					t.Fatal(err)
				}
				hTestECHHandshake(t, server, client)
			})
		}
	}
}

func hTestECHHandshake(t *testing.T, server ServerConfig, client Config) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	clientRaw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientRaw.Close()
	serverRaw, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer serverRaw.Close()
	type result struct {
		accepted   bool
		serverName string
		err        error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := ServerHandshake(context.Background(), serverRaw, server)
		if err != nil {
			done <- result{err: err}
			return
		}
		state := conn.ConnectionState()
		done <- result{accepted: state.ECHAccepted, serverName: state.ServerName}
	}()
	conn, err := ClientHandshake(context.Background(), clientRaw, client)
	if err != nil {
		clientRaw.Close()
		t.Fatal("client: ", err, "; server: ", (<-done).err)
	}
	serverResult := <-done
	if serverResult.err != nil {
		t.Fatal("server: ", serverResult.err)
	}
	if !serverResult.accepted || serverResult.serverName != "example.org" {
		t.Fatalf("server: ECH accepted %v, server name %q", serverResult.accepted, serverResult.serverName)
	}
	if !conn.ConnectionState().ECHAccepted {
		t.Fatal("client does not report ECH as accepted")
	}
}

// TestH_UTLSRandomizedRetry dials a Go server, which prefers X25519MLKEM768, with randomized
// specs. Those offering the group without a key share got a HelloRetryRequest that uTLS cannot
// answer ("tls: CurvePreferences includes unsupported curve").
func TestH_UTLSRandomizedRetry(t *testing.T) {
	keyPEM, certPEM, err := GenerateCertificate(nil, nil, time.Now, "example.org", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	logger := log.NewNOPFactory().Logger()
	server, err := NewServer(context.Background(), logger, option.InboundTLSOptions{
		Enabled: true, ServerName: "example.org",
		Certificate: []string{string(certPEM)}, Key: []string{string(keyPEM)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	// Xray's names are not seeded: each connection draws a new spec.
	for _, fingerprint := range []string{"randomized", "hellorandomized", "hellorandomizedalpn", "hellorandomizednoalpn"} {
		t.Run(fingerprint, func(t *testing.T) {
			client, err := NewClient(context.Background(), logger, "example.org", option.OutboundTLSOptions{
				Enabled: true, ServerName: "example.org", Insecure: true,
				UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint},
			})
			if err != nil {
				t.Fatal(err)
			}
			for range 30 {
				hTestHandshake(t, server, client)
			}
		})
	}
}

func hTestHandshake(t *testing.T, server ServerConfig, client Config) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	clientRaw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientRaw.Close()
	serverRaw, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer serverRaw.Close()
	go ServerHandshake(context.Background(), serverRaw, server)
	if _, err = ClientHandshake(context.Background(), clientRaw, client); err != nil {
		t.Fatal(err)
	}
}

package box_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sJSON "github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

const hVLESSUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// hSelfSignedPEM returns a certificate and key for 127.0.0.1 / example.com.
func hSelfSignedPEM(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

// hVLESSEncryptionPair returns matching server decryption / client encryption strings.
func hVLESSEncryptionPair(t *testing.T, mode string) (string, string) {
	t.Helper()
	encode := base64.RawURLEncoding.EncodeToString
	x25519Key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	mlkemKey, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	decryption := "mlkem768x25519plus." + mode + ".600s." + encode(mlkemKey.Bytes()) + "." + encode(x25519Key.Bytes())
	encryption := "mlkem768x25519plus." + mode + ".1rtt." + encode(mlkemKey.EncapsulationKey().Bytes()) + "." + encode(x25519Key.PublicKey().Bytes())
	return decryption, encryption
}

// hTLSEchoServer echoes everything inside a TLS 1.3 session, so Vision sees real inner TLS.
func hTLSEchoServer(t *testing.T, certPEM, keyPEM string) string {
	t.Helper()
	certificate, err := stdtls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	require.NoError(t, err)
	listener, err := stdtls.Listen("tcp", "127.0.0.1:0", &stdtls.Config{Certificates: []stdtls.Certificate{certificate}, MinVersion: stdtls.VersionTLS13})
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
	return listener.Addr().String()
}

type hVLESSCase struct {
	name       string
	tls        bool
	flow       string
	encryption string // "", native, xorpub, random
}

func TestH_VLESSVisionAndEncryptionModes(t *testing.T) {
	certPEM, keyPEM := hSelfSignedPEM(t)
	target := hTLSEchoServer(t, certPEM, keyPEM)
	cases := []hVLESSCase{
		{name: "tls", tls: true},
		{name: "tls-vision", tls: true, flow: "xtls-rprx-vision"},
		{name: "encryption-native", encryption: "native"},
		{name: "encryption-xorpub", encryption: "xorpub"},
		{name: "encryption-random", encryption: "random"},
		{name: "encryption-native-vision", encryption: "native", flow: "xtls-rprx-vision"},
		{name: "encryption-xorpub-vision", encryption: "xorpub", flow: "xtls-rprx-vision"},
		{name: "encryption-random-vision", encryption: "random", flow: "xtls-rprx-vision"},
		{name: "tls-encryption-vision", tls: true, encryption: "native", flow: "xtls-rprx-vision"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			mixedPort := hStartVLESSBox(t, testCase, certPEM, keyPEM)
			hVLESSRoundTrip(t, mixedPort, target)
		})
	}
}

func hStartVLESSBox(t *testing.T, testCase hVLESSCase, certPEM, keyPEM string) int {
	t.Helper()
	vlessPort := hFreeTCPPort(t)
	mixedPort := hFreeTCPPort(t)
	user := map[string]any{"name": "u", "uuid": hVLESSUUID, "flow": testCase.flow}
	inbound := map[string]any{"type": "vless", "tag": "vless-in", "listen": "127.0.0.1", "listen_port": vlessPort, "users": []any{user}}
	outbound := map[string]any{"type": "vless", "tag": "vless-out", "server": "127.0.0.1", "server_port": vlessPort, "uuid": hVLESSUUID, "flow": testCase.flow}
	if testCase.tls {
		inbound["tls"] = map[string]any{"enabled": true, "server_name": "example.com", "certificate": certPEM, "key": keyPEM}
		outbound["tls"] = map[string]any{"enabled": true, "server_name": "example.com", "insecure": true}
	}
	if testCase.encryption != "" {
		decryption, encryption := hVLESSEncryptionPair(t, testCase.encryption)
		inbound["decryption"] = decryption
		outbound["encryption"] = encryption
	}
	config := map[string]any{
		"log":       map[string]any{"disabled": true},
		"inbounds":  []any{inbound, map[string]any{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": mixedPort}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}, outbound},
		"route": map[string]any{"rules": []any{
			map[string]any{"inbound": []string{"mixed-in"}, "outbound": "vless-out"},
			map[string]any{"inbound": []string{"vless-in"}, "outbound": "direct"},
		}},
	}
	content, err := json.Marshal(config)
	require.NoError(t, err)
	ctx := include.Context(context.Background())
	options, err := sJSON.UnmarshalExtendedContext[option.Options](ctx, content)
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	t.Cleanup(func() { instance.Close() })
	require.NoError(t, instance.Start())
	return mixedPort
}

// hVLESSRoundTrip opens a TLS 1.3 session to the echo server through the mixed inbound and
// sends a megabyte each way, in pieces, so Vision has to pad, reshape and switch to direct.
func hVLESSRoundTrip(t *testing.T, mixedPort int, target string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(mixedPort), 2*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(20*time.Second)))
	_, err = conn.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))
	require.NoError(t, err)
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	tlsConn := stdtls.Client(&hBufferedConn{Conn: conn, reader: reader}, &stdtls.Config{InsecureSkipVerify: true, MinVersion: stdtls.VersionTLS13})
	require.NoError(t, tlsConn.Handshake())
	payload := make([]byte, 1<<20)
	_, err = rand.Read(payload)
	require.NoError(t, err)
	writeErr := make(chan error, 1)
	go func() {
		for offset := 0; offset < len(payload); offset += 16 * 1024 {
			end := min(offset+16*1024, len(payload))
			if _, err := tlsConn.Write(payload[offset:end]); err != nil {
				writeErr <- err
				return
			}
		}
		writeErr <- nil
	}()
	echo := make([]byte, len(payload))
	_, err = io.ReadFull(tlsConn, echo)
	require.NoError(t, err)
	require.NoError(t, <-writeErr)
	require.True(t, bytes.Equal(payload, echo), "echoed data differs")
}

type hBufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *hBufferedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

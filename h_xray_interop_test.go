package box_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"

	"github.com/stretchr/testify/require"
)

// Interop tests against real Xray binaries. Xray servers allow loopback in freedom: since 26.10
// it blocks private addresses for proxied connections by default.
//
// Interop tests against real Xray binaries. HIDDIFY_XRAY lists them, separated by ":"; the tests
// skip when it is empty.
func hXrayBinaries(t *testing.T) []string {
	t.Helper()
	value := os.Getenv("HIDDIFY_XRAY")
	if value == "" {
		t.Skip("HIDDIFY_XRAY is not set")
	}
	return strings.Split(value, ":")
}

func hXrayVersion(t *testing.T, binary string) string {
	output, err := exec.Command(binary, "version").Output()
	require.NoError(t, err)
	return strings.Fields(string(output))[1]
}

// hStartXray runs binary with config until the test ends and waits for TCP port to accept; with
// port 0 (a UDP inbound) it waits a moment instead.
func hStartXray(t *testing.T, binary string, config string, port int) {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o600))
	command := exec.Command(binary, "run", "-c", configPath)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	require.NoError(t, command.Start())
	t.Cleanup(func() {
		command.Process.Kill()
		command.Wait()
		if t.Failed() {
			t.Log("xray output:\n" + output.String())
		}
	})
	if port == 0 {
		time.Sleep(time.Second)
		require.Nil(t, command.ProcessState, "xray exited")
		return
	}
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 100*time.Millisecond)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}, 10*time.Second, 50*time.Millisecond, "xray did not start")
}

func hStartEcho(t *testing.T) string {
	t.Helper()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return echo.Addr().String()
}

// hEchoThroughSOCKS sends data through a SOCKS5 proxy to the echo server and checks the reply.
func hEchoThroughSOCKS(t *testing.T, proxyPort int, echoAddress string) {
	t.Helper()
	client := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", uint16(proxyPort)), socks.Version5, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(echoAddress))
	require.NoError(t, err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	payload := bytes.Repeat([]byte("hiddify interop "), 4096)
	go conn.Write(payload)
	reply := make([]byte, len(payload))
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, payload, reply)
}

func hStartInteropBox(t *testing.T, config string, configure func(options *option.Options)) {
	t.Helper()
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
	require.NoError(t, err)
	if configure != nil {
		configure(&options)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	t.Cleanup(func() { instance.Close() })
	require.NoError(t, instance.Start())
}

const hInteropUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// gRPC service names, plain and Xray's custom paths, in both directions and with both sing-box
// gRPC implementations.
func TestH_XrayGRPCServiceName(t *testing.T) {
	binaries := hXrayBinaries(t)
	echoAddress := hStartEcho(t)
	for _, binary := range binaries {
		version := hXrayVersion(t, binary)
		for _, names := range []struct {
			xrayServer string
			client     string
			server     string
		}{
			{"TunService", "TunService", "TunService"},
			{"/my/path/Tun|TunMulti", "/my/path/Tun", "/my/path/Tun"},
			{"/a/b/c/stream|multi", "/a/b/c/stream", "/a/b/c/stream"},
		} {
			for _, lite := range []bool{false, true} {
				implementation := "grpc"
				if lite {
					implementation = "grpc-lite"
				}
				forceLite := func(options *option.Options) {
					for _, inbound := range options.Inbounds {
						if vless, isVLESS := inbound.Options.(*option.VLESSInboundOptions); isVLESS && vless.Transport != nil {
							vless.Transport.GRPCOptions.ForceLite = lite
						}
					}
					for _, outbound := range options.Outbounds {
						if vless, isVLESS := outbound.Options.(*option.VLESSOutboundOptions); isVLESS && vless.Transport != nil {
							vless.Transport.GRPCOptions.ForceLite = lite
						}
					}
				}
				t.Run(version+"/"+implementation+"/"+names.client+"/sing-box to xray", func(t *testing.T) {
					xrayPort := hFreeTCPPort(t)
					hStartXray(t, binary, `{
						"log": {"loglevel": "warning"},
						"inbounds": [{"listen": "127.0.0.1", "port": `+strconv.Itoa(xrayPort)+`, "protocol": "vless",
							"settings": {"clients": [{"id": "`+hInteropUUID+`"}], "decryption": "none"},
							"streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "`+names.xrayServer+`"}}}],
						"outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}]
					}`, xrayPort)
					mixedPort := hFreeTCPPort(t)
					hStartInteropBox(t, `{
						"log": {"disabled": true},
						"inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(mixedPort)+`}],
						"outbounds": [{"type": "vless", "server": "127.0.0.1", "server_port": `+strconv.Itoa(xrayPort)+`,
							"uuid": "`+hInteropUUID+`", "transport": {"type": "grpc", "service_name": "`+names.client+`"}}]
					}`, forceLite)
					hEchoThroughSOCKS(t, mixedPort, echoAddress)
				})
				t.Run(version+"/"+implementation+"/"+names.client+"/xray to sing-box", func(t *testing.T) {
					serverPort := hFreeTCPPort(t)
					hStartInteropBox(t, `{
						"log": {"disabled": true},
						"inbounds": [{"type": "vless", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(serverPort)+`,
							"users": [{"uuid": "`+hInteropUUID+`"}], "transport": {"type": "grpc", "service_name": "`+names.server+`"}}],
						"outbounds": [{"type": "direct"}]
					}`, forceLite)
					socksPort := hFreeTCPPort(t)
					hStartXray(t, binary, `{
						"log": {"loglevel": "warning"},
						"inbounds": [{"listen": "127.0.0.1", "port": `+strconv.Itoa(socksPort)+`, "protocol": "socks", "settings": {"udp": false}}],
						"outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": `+strconv.Itoa(serverPort)+`,
							"users": [{"id": "`+hInteropUUID+`", "encryption": "none"}]}]},
							"streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "`+names.client+`"}}}]
					}`, socksPort)
					hEchoThroughSOCKS(t, socksPort, echoAddress)
				})
			}
		}
	}
}

// XHTTP over plain HTTP, with the default padding and with x_padding_obfs_mode placing the
// padding in a header, in both directions.
func TestH_XrayXHTTP(t *testing.T) {
	binaries := hXrayBinaries(t)
	echoAddress := hStartEcho(t)
	for _, binary := range binaries {
		version := hXrayVersion(t, binary)
		for _, variant := range []struct {
			name    string
			xray    string
			singBox string
		}{
			{"packet-up", `"mode": "packet-up", "path": "/xh"`, `"mode": "packet-up", "path": "/xh"`},
			{"packet-up obfs header",
				`"mode": "packet-up", "path": "/xh", "xPaddingObfsMode": true, "xPaddingPlacement": "header", "xPaddingHeader": "X-Pad", "xPaddingKey": "x_pad"`,
				`"mode": "packet-up", "path": "/xh", "x_padding_obfs_mode": true, "x_padding_placement": "header", "x_padding_header": "X-Pad", "x_padding_key": "x_pad"`},
		} {
			t.Run(version+"/"+variant.name+"/sing-box to xray", func(t *testing.T) {
				xrayPort := hFreeTCPPort(t)
				hStartXray(t, binary, `{
					"log": {"loglevel": "warning"},
					"inbounds": [{"listen": "127.0.0.1", "port": `+strconv.Itoa(xrayPort)+`, "protocol": "vless",
						"settings": {"clients": [{"id": "`+hInteropUUID+`"}], "decryption": "none"},
						"streamSettings": {"network": "xhttp", "xhttpSettings": {`+variant.xray+`}}}],
					"outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}]
				}`, xrayPort)
				mixedPort := hFreeTCPPort(t)
				hStartInteropBox(t, `{
					"log": {"disabled": true},
					"inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(mixedPort)+`}],
					"outbounds": [{"type": "vless", "server": "127.0.0.1", "server_port": `+strconv.Itoa(xrayPort)+`,
						"uuid": "`+hInteropUUID+`", "transport": {"type": "xhttp", `+variant.singBox+`}}]
				}`, nil)
				hEchoThroughSOCKS(t, mixedPort, echoAddress)
			})
			t.Run(version+"/"+variant.name+"/xray to sing-box", func(t *testing.T) {
				serverPort := hFreeTCPPort(t)
				hStartInteropBox(t, `{
					"log": {"disabled": true},
					"inbounds": [{"type": "vless", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(serverPort)+`,
						"users": [{"uuid": "`+hInteropUUID+`"}], "transport": {"type": "xhttp", `+variant.singBox+`}}],
					"outbounds": [{"type": "direct"}]
				}`, nil)
				socksPort := hFreeTCPPort(t)
				hStartXray(t, binary, `{
					"log": {"loglevel": "warning"},
					"inbounds": [{"listen": "127.0.0.1", "port": `+strconv.Itoa(socksPort)+`, "protocol": "socks", "settings": {"udp": false}}],
					"outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": `+strconv.Itoa(serverPort)+`,
						"users": [{"id": "`+hInteropUUID+`", "encryption": "none"}]}]},
						"streamSettings": {"network": "xhttp", "xhttpSettings": {`+variant.xray+`}}}]
				}`, socksPort)
				hEchoThroughSOCKS(t, socksPort, echoAddress)
			})
		}
	}
}

// hREALITYKeys returns an X25519 key pair in Xray's encoding.
func hREALITYKeys(t *testing.T) (private string, public string) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(key.Bytes()), base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
}

// REALITY with the default (hybrid X25519MLKEM768) key share and with key_share "classical",
// for several fingerprints. Xray servers from v26.9.8 require the hybrid share, so "classical"
// only works with older ones.
func TestH_XrayREALITYKeyShare(t *testing.T) {
	binaries := hXrayBinaries(t)
	echoAddress := hStartEcho(t)
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer target.Close()
	for _, binary := range binaries {
		version := hXrayVersion(t, binary)
		newServer := !strings.HasPrefix(version, "26.3.")
		privateKey, publicKey := hREALITYKeys(t)
		xrayPort := hFreeTCPPort(t)
		hStartXray(t, binary, `{
			"log": {"loglevel": "warning"},
			"inbounds": [{"listen": "127.0.0.1", "port": `+strconv.Itoa(xrayPort)+`, "protocol": "vless",
				"settings": {"clients": [{"id": "`+hInteropUUID+`"}], "decryption": "none"},
				"streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
					"target": "`+target.Listener.Addr().String()+`", "serverNames": ["example.com"],
					"privateKey": "`+privateKey+`", "shortIds": ["0123abcd"]}}}],
			"outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}]
		}`, xrayPort)
		for _, fragment := range []string{"fragment", "record_fragment"} {
			t.Run(version+"/chrome/"+fragment, func(t *testing.T) {
				mixedPort := hFreeTCPPort(t)
				hStartInteropBox(t, `{
					"log": {"disabled": true},
					"inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(mixedPort)+`}],
					"outbounds": [{"type": "vless", "server": "127.0.0.1", "server_port": `+strconv.Itoa(xrayPort)+`,
						"uuid": "`+hInteropUUID+`", "tls": {"enabled": true, "server_name": "example.com", "`+fragment+`": true,
							"utls": {"enabled": true, "fingerprint": "chrome"},
							"reality": {"enabled": true, "public_key": "`+publicKey+`", "short_id": "0123abcd"}}}]
				}`, nil)
				hEchoThroughSOCKS(t, mixedPort, echoAddress)
			})
		}
		for _, keyShare := range []string{"", "classical"} {
			for _, fingerprint := range []string{"chrome", "firefox", "safari", "edge"} {
				t.Run(version+"/"+fingerprint+"/key_share="+keyShare, func(t *testing.T) {
					mixedPort := hFreeTCPPort(t)
					hStartInteropBox(t, `{
						"log": {"disabled": true},
						"inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(mixedPort)+`}],
						"outbounds": [{"type": "vless", "server": "127.0.0.1", "server_port": `+strconv.Itoa(xrayPort)+`,
							"uuid": "`+hInteropUUID+`", "tls": {"enabled": true, "server_name": "example.com",
								"utls": {"enabled": true, "fingerprint": "`+fingerprint+`"},
								"reality": {"enabled": true, "public_key": "`+publicKey+`", "short_id": "0123abcd", "key_share": "`+keyShare+`"}}}]
					}`, nil)
					if keyShare == "classical" && newServer {
						client := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", uint16(mixedPort)), socks.Version5, "", "")
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						conn, err := client.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(echoAddress))
						if err == nil {
							defer conn.Close()
							conn.SetDeadline(time.Now().Add(3 * time.Second))
							conn.Write([]byte("ping"))
							_, err = io.ReadFull(conn, make([]byte, 4))
						}
						require.Error(t, err, "a v26.9.8+ server takes no classical ClientHello")
						return
					}
					hEchoThroughSOCKS(t, mixedPort, echoAddress)
				})
			}
		}
	}
}

// VLESS encryption, with and without Vision and TLS, in both directions.
func TestH_XrayVLESSEncryption(t *testing.T) {
	binaries := hXrayBinaries(t)
	certPEM, keyPEM := hSelfSignedPEM(t)
	target := hTLSEchoServer(t, certPEM, keyPEM)
	certDir := t.TempDir()
	certFile, keyFile := filepath.Join(certDir, "cert.pem"), filepath.Join(certDir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, []byte(certPEM), 0o600))
	require.NoError(t, os.WriteFile(keyFile, []byte(keyPEM), 0o600))
	block, _ := pem.Decode([]byte(certPEM))
	certSum := sha256.Sum256(block.Bytes)
	certHash := hex.EncodeToString(certSum[:]) // the Xray client pins the test certificate
	cases := []hVLESSCase{
		{name: "native", encryption: "native"},
		{name: "xorpub", encryption: "xorpub"},
		{name: "random", encryption: "random"},
		{name: "native-vision", encryption: "native", flow: "xtls-rprx-vision"},
		{name: "xorpub-vision", encryption: "xorpub", flow: "xtls-rprx-vision"},
		{name: "random-vision", encryption: "random", flow: "xtls-rprx-vision"},
		{name: "tls-native-vision", tls: true, encryption: "native", flow: "xtls-rprx-vision"},
		{name: "tls-random-vision", tls: true, encryption: "random", flow: "xtls-rprx-vision"},
	}
	for _, binary := range binaries {
		version := hXrayVersion(t, binary)
		for _, testCase := range cases {
			decryption, encryption := hVLESSEncryptionPair(t, testCase.encryption)
			xrayTLS := `"security": "none"`
			if testCase.tls {
				xrayTLS = `"security": "tls", "tlsSettings": {"serverName": "example.com",
					"certificates": [{"certificateFile": "` + certFile + `", "keyFile": "` + keyFile + `"}]}`
			}
			t.Run(version+"/sing-box-client/"+testCase.name, func(t *testing.T) {
				xrayPort := hFreeTCPPort(t)
				hStartXray(t, binary, `{
					"log": {"loglevel": "warning"},
					"inbounds": [{"listen": "127.0.0.1", "port": `+strconv.Itoa(xrayPort)+`, "protocol": "vless",
						"settings": {"clients": [{"id": "`+hInteropUUID+`", "flow": "`+testCase.flow+`"}], "decryption": "`+decryption+`"},
						"streamSettings": {"network": "tcp", `+xrayTLS+`}}],
					"outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}]
				}`, xrayPort)
				tls := ""
				if testCase.tls {
					tls = `, "tls": {"enabled": true, "server_name": "example.com", "insecure": true}`
				}
				mixedPort := hFreeTCPPort(t)
				hStartInteropBox(t, `{
					"log": {"disabled": true},
					"inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(mixedPort)+`}],
					"outbounds": [{"type": "vless", "server": "127.0.0.1", "server_port": `+strconv.Itoa(xrayPort)+`,
						"uuid": "`+hInteropUUID+`", "flow": "`+testCase.flow+`", "encryption": "`+encryption+`"`+tls+`}]
				}`, nil)
				hVLESSRoundTrip(t, mixedPort, target)
			})
			t.Run(version+"/xray-client/"+testCase.name, func(t *testing.T) {
				vlessPort := hFreeTCPPort(t)
				tls := ""
				if testCase.tls {
					tls = `, "tls": {"enabled": true, "server_name": "example.com", "certificate_path": "` + certFile + `", "key_path": "` + keyFile + `"}`
				}
				hStartInteropBox(t, `{
					"log": {"disabled": true},
					"inbounds": [{"type": "vless", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(vlessPort)+`,
						"users": [{"uuid": "`+hInteropUUID+`", "flow": "`+testCase.flow+`"}], "decryption": "`+decryption+`"`+tls+`}],
					"outbounds": [{"type": "direct"}]
				}`, nil)
				httpPort := hFreeTCPPort(t)
				hStartXray(t, binary, `{
					"log": {"loglevel": "warning"},
					"inbounds": [{"listen": "127.0.0.1", "port": `+strconv.Itoa(httpPort)+`, "protocol": "http"}],
					"outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": `+strconv.Itoa(vlessPort)+`,
						"users": [{"id": "`+hInteropUUID+`", "flow": "`+testCase.flow+`", "encryption": "`+encryption+`"}]}]},
						"streamSettings": {"network": "tcp", `+strings.Replace(xrayTLS, `"certificates": [{"certificateFile": "`+certFile+`", "keyFile": "`+keyFile+`"}]`, `"pinnedPeerCertSha256": "`+certHash+`"`, 1)+`}}]
				}`, httpPort)
				hVLESSRoundTrip(t, httpPort, target)
			})
		}
	}
}

// XHTTP auto mode over REALITY picks what Xray's client picks (stream-one), so it works with an
// Xray server that allows only stream-one.
func TestH_XrayXHTTPAutoOverREALITY(t *testing.T) {
	binaries := hXrayBinaries(t)
	echoAddress := hStartEcho(t)
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer target.Close()
	for _, binary := range binaries {
		version := hXrayVersion(t, binary)
		for _, serverMode := range []string{"auto", "stream-one"} {
			t.Run(version+"/server="+serverMode, func(t *testing.T) {
				privateKey, publicKey := hREALITYKeys(t)
				xrayPort := hFreeTCPPort(t)
				hStartXray(t, binary, `{
					"log": {"loglevel": "warning"},
					"inbounds": [{"listen": "127.0.0.1", "port": `+strconv.Itoa(xrayPort)+`, "protocol": "vless",
						"settings": {"clients": [{"id": "`+hInteropUUID+`"}], "decryption": "none"},
						"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/x", "mode": "`+serverMode+`"},
							"security": "reality", "realitySettings": {"target": "`+target.Listener.Addr().String()+`",
							"serverNames": ["example.com"], "privateKey": "`+privateKey+`", "shortIds": ["0123abcd"]}}}],
					"outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}]
				}`, xrayPort)
				mixedPort := hFreeTCPPort(t)
				hStartInteropBox(t, `{
					"log": {"disabled": true},
					"inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(mixedPort)+`}],
					"outbounds": [{"type": "vless", "server": "127.0.0.1", "server_port": `+strconv.Itoa(xrayPort)+`,
						"uuid": "`+hInteropUUID+`", "transport": {"type": "xhttp", "path": "/x", "mode": "auto"},
						"tls": {"enabled": true, "server_name": "example.com", "utls": {"enabled": true, "fingerprint": "chrome"},
							"reality": {"enabled": true, "public_key": "`+publicKey+`", "short_id": "0123abcd"}}}]
				}`, nil)
				hEchoThroughSOCKS(t, mixedPort, echoAddress)
			})
		}
	}
}

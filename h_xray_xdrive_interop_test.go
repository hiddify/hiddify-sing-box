//go:build with_xdrive

package box_test

import (
	"strconv"
	"strings"
	"testing"
)

// XDRIVE between sing-box and Xray, through a shared folder (XDRIVE's "local" service), in both
// directions. Xray allows XDRIVE only for VLESS with encryption, and its client only with mux.
func TestH_XrayXDrive(t *testing.T) {
	binaries := hXrayBinaries(t)
	certPEM, keyPEM := hSelfSignedPEM(t)
	target := hTLSEchoServer(t, certPEM, keyPEM)
	for _, binary := range binaries {
		version := hXrayVersion(t, binary)
		if !hXrayAtLeast(version, 26, 10) {
			continue // XDRIVE came in Xray 26.10
		}
		decryption, encryption := hVLESSEncryptionPair(t, "native")
		t.Run(version+"/sing-box-client", func(t *testing.T) {
			folder := t.TempDir()
			hStartXray(t, binary, `{
				"log": {"loglevel": "warning"},
				"inbounds": [{"listen": "127.0.0.1", "port": `+strconv.Itoa(hFreeTCPPort(t))+`, "protocol": "vless",
					"settings": {"clients": [{"id": "`+hInteropUUID+`"}], "decryption": "`+decryption+`"},
					"streamSettings": {"network": "xdrive", "xdriveSettings": {"service": "local", "remoteFolder": "`+folder+`", "pollIntervalMs": 20}}}],
				"outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}]
			}`, 0)
			mixedPort := hFreeTCPPort(t)
			hStartInteropBox(t, `{
				"log": {"disabled": true},
				"inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(mixedPort)+`}],
				"outbounds": [{"type": "vless", "server": "127.0.0.1", "server_port": 1, "uuid": "`+hInteropUUID+`",
					"encryption": "`+encryption+`",
					"transport": {"type": "xdrive", "service": "local", "remote_folder": "`+folder+`", "poll_interval_ms": 20}}]
			}`, nil)
			hVLESSRoundTrip(t, mixedPort, target)
		})
		t.Run(version+"/xray-client", func(t *testing.T) {
			folder := t.TempDir()
			hStartInteropBox(t, `{
				"log": {"disabled": true},
				"inbounds": [{"type": "vless", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(hFreeTCPPort(t))+`,
					"users": [{"uuid": "`+hInteropUUID+`"}], "decryption": "`+decryption+`",
					"transport": {"type": "xdrive", "service": "local", "remote_folder": "`+folder+`", "poll_interval_ms": 20}}],
				"outbounds": [{"type": "direct"}]
			}`, nil)
			httpPort := hFreeTCPPort(t)
			hStartXray(t, binary, `{
				"log": {"loglevel": "warning"},
				"inbounds": [{"listen": "127.0.0.1", "port": `+strconv.Itoa(httpPort)+`, "protocol": "http"}],
				"outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": 1,
					"users": [{"id": "`+hInteropUUID+`", "encryption": "`+encryption+`"}]}]},
					"mux": {"enabled": true, "concurrency": 8},
					"streamSettings": {"network": "xdrive", "xdriveSettings": {"service": "local", "remoteFolder": "`+folder+`", "pollIntervalMs": 20}}}]
			}`, httpPort)
			hVLESSRoundTrip(t, httpPort, target)
			hVLESSRoundTrip(t, httpPort, target)
		})
	}
}

// hXrayAtLeast compares the year and month of an Xray version "26.10.31".
func hXrayAtLeast(version string, year, month int) bool {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return false
	}
	gotYear, _ := strconv.Atoi(parts[0])
	gotMonth, _ := strconv.Atoi(parts[1])
	return gotYear > year || gotYear == year && gotMonth >= month
}

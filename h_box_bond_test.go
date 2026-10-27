//go:build with_bond

package box_test

import (
	"strconv"
	"testing"
)

// two VLESS legs bonded with uneven ratios each way, carrying more than one 64 KiB frame
func TestH_Bond(t *testing.T) {
	echoAddress := hStartEcho(t)
	legA, legB := hFreeTCPPort(t), hFreeTCPPort(t)
	mixedPort := hFreeTCPPort(t)
	vlessLeg := func(port int) string {
		return `{"type": "vless", "server": "127.0.0.1", "server_port": ` + strconv.Itoa(port) + `, "uuid": "` + hInteropUUID + `"}`
	}
	vlessInbound := func(port int) string {
		return `{"type": "vless", "listen": "127.0.0.1", "listen_port": ` + strconv.Itoa(port) + `, "users": [{"uuid": "` + hInteropUUID + `"}]}`
	}
	hStartInteropBox(t, `{
		"log": {"disabled": true},
		"inbounds": [
			{"type": "bond", "tag": "bond-in", "inbounds": [`+vlessInbound(legA)+`, `+vlessInbound(legB)+`]},
			{"type": "mixed", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(mixedPort)+`}
		],
		"outbounds": [
			{"type": "bond", "tag": "bond", "outbounds": [
				{"outbound": `+vlessLeg(legA)+`, "download_ratio": 30, "upload_ratio": 60},
				{"outbound": `+vlessLeg(legB)+`, "download_ratio": 70, "upload_ratio": 40}
			]},
			{"type": "direct", "tag": "direct"}
		],
		"route": {"rules": [{"inbound": "bond-in", "outbound": "direct"}], "final": "bond"}
	}`, nil)
	for range 3 {
		hEchoThroughSOCKS(t, mixedPort, echoAddress)
	}
}

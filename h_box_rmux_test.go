package box_test

import (
	"strconv"
	"testing"
)

// VLESS with multiplex over each protocol, rmux included
func TestH_MultiplexRMux(t *testing.T) {
	echoAddress := hStartEcho(t)
	for _, protocol := range []string{"rmux", "h2mux", "smux"} {
		t.Run(protocol, func(t *testing.T) {
			vlessPort := hFreeTCPPort(t)
			mixedPort := hFreeTCPPort(t)
			hStartInteropBox(t, `{
				"log": {"disabled": true},
				"inbounds": [
					{"type": "vless", "tag": "vless-in", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(vlessPort)+`, "users": [{"uuid": "`+hInteropUUID+`"}], "multiplex": {"enabled": true}},
					{"type": "mixed", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(mixedPort)+`}
				],
				"outbounds": [
					{"type": "vless", "tag": "vless", "server": "127.0.0.1", "server_port": `+strconv.Itoa(vlessPort)+`, "uuid": "`+hInteropUUID+`",
						"multiplex": {"enabled": true, "protocol": "`+protocol+`", "max_connections": 1}},
					{"type": "direct", "tag": "direct"}
				],
				"route": {"rules": [{"inbound": "vless-in", "outbound": "direct"}], "final": "vless"}
			}`, nil)
			for range 3 {
				hEchoThroughSOCKS(t, mixedPort, echoAddress)
			}
		})
	}
}

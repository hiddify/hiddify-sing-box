//go:build with_sudoku

package box_test

import (
	"strconv"
	"testing"
)

// Sudoku between two boxes, plain and with the HTTP mask
func TestH_Sudoku(t *testing.T) {
	echoAddress := hStartEcho(t)
	for _, variant := range []struct{ name, inbound, outbound string }{
		{"plain", `, "disable_http_mask": true`, `, "http_mask": {"enabled": false}`},
		{"http-mask", ``, `, "http_mask": {"enabled": true}`},
		{"ascii", `, "table_type": "prefer_ascii", "disable_http_mask": true`, `, "table_type": "prefer_ascii", "http_mask": {"enabled": false}`},
	} {
		t.Run(variant.name, func(t *testing.T) {
			sudokuPort := hFreeTCPPort(t)
			mixedPort := hFreeTCPPort(t)
			hStartInteropBox(t, `{
				"log": {"disabled": true},
				"inbounds": [
					{"type": "sudoku", "tag": "sudoku-in", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(sudokuPort)+`, "key": "hiddify-test-key"`+variant.inbound+`},
					{"type": "mixed", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(mixedPort)+`}
				],
				"outbounds": [
					{"type": "sudoku", "tag": "sudoku", "server": "127.0.0.1", "server_port": `+strconv.Itoa(sudokuPort)+`, "key": "hiddify-test-key"`+variant.outbound+`},
					{"type": "direct", "tag": "direct"}
				],
				"route": {"rules": [{"inbound": "sudoku-in", "outbound": "direct"}], "final": "sudoku"}
			}`, nil)
			hEchoThroughSOCKS(t, mixedPort, echoAddress)
		})
	}
}

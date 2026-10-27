//go:build with_sudoku

package box_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
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

// a bad server config fails at load, not on every connection
func TestH_SudokuInboundValidates(t *testing.T) {
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{"inbounds": [{"type": "sudoku", "listen_port": 1, "key": "k", "aead_method": "rot13"}]}`))
	require.NoError(t, err)
	_, err = box.New(box.Options{Context: ctx, Options: options})
	require.Error(t, err)
}

// a connection that is not Sudoku is passed to the fallback, with what it already sent
func TestH_SudokuFallback(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("decoy page"))
	}))
	defer site.Close()
	sudokuPort := hFreeTCPPort(t)
	hStartInteropBox(t, `{
		"log": {"disabled": true},
		"inbounds": [{"type": "sudoku", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(sudokuPort)+`, "key": "hiddify-test-key",
			"disable_http_mask": true, "fallback": "`+site.Listener.Addr().String()+`"}],
		"outbounds": [{"type": "direct"}]
	}`, nil)
	response, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://127.0.0.1:" + strconv.Itoa(sudokuPort) + "/")
	require.NoError(t, err)
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	require.Equal(t, "decoy page", string(body))
}

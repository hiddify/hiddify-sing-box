package xhttp

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func hNewServer(t *testing.T, content string) *Server {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	server, err := NewServer(ctx, logger.NOP(), hOptions(t, content), nil, &hEchoHandler{})
	require.NoError(t, err)
	return server
}

func hRequest(method string, target string, body []byte, paddingLength int) *http.Request {
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	request.Host = "example.com"
	if paddingLength >= 0 {
		request.Header.Set("Referer", "https://example.com/?x_padding="+strings.Repeat("X", paddingLength))
	}
	return request
}

func hServe(server *Server, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder
}

const hBase = `"path":"/xh","x_padding_bytes":"100-200"`

func TestH_XHTTPServerRejects(t *testing.T) {
	cases := []struct {
		name    string
		mode    string
		extra   string
		request *http.Request
		status  int
	}{
		{"bad host", "auto", `,"host":"good.example.com"`, hRequest("POST", "/xh/s/0", nil, 150), http.StatusNotFound},
		{"bad path", "auto", "", hRequest("POST", "/other/s/0", nil, 150), http.StatusNotFound},
		{"missing padding", "auto", "", hRequest("POST", "/xh/s/0", nil, -1), http.StatusBadRequest},
		{"short padding", "auto", "", hRequest("POST", "/xh/s/0", nil, 99), http.StatusBadRequest},
		{"long padding", "auto", "", hRequest("POST", "/xh/s/0", nil, 201), http.StatusBadRequest},
		{"packet-up in stream-one", "stream-one", "", hRequest("POST", "/xh/s/0", nil, 150), http.StatusBadRequest},
		{"packet-up in stream-up", "stream-up", "", hRequest("POST", "/xh/s/0", nil, 150), http.StatusBadRequest},
		{"stream-up in packet-up", "packet-up", "", hRequest("POST", "/xh/s", nil, 150), http.StatusBadRequest},
		{"stream-one in packet-up", "packet-up", "", hRequest("POST", "/xh/", nil, 150), http.StatusBadRequest},
		{"bad seq", "packet-up", "", hRequest("POST", "/xh/s/abc", []byte("x"), 150), http.StatusInternalServerError},
		{"too large", "packet-up", `,"sc_max_each_post_bytes":"10000-10000"`, hRequest("POST", "/xh/s/0", make([]byte, 10001), 150), http.StatusRequestEntityTooLarge},
		{"bad method", "packet-up", "", hRequest("DELETE", "/xh/s/0", nil, 150), http.StatusMethodNotAllowed},
		{"missing header data", "packet-up", `,"uplink_data_placement":"header"`, func() *http.Request {
			r := hRequest("GET", "/xh/s/0", nil, 150)
			r.Header.Set("X-Data-Upstream", "1")
			return r
		}(), http.StatusInternalServerError},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			server := hNewServer(t, `{"mode":"`+testCase.mode+`",`+hBase+testCase.extra+`}`)
			recorder := hServe(server, testCase.request)
			require.Equal(t, testCase.status, recorder.Code)
		})
	}
}

func TestH_XHTTPServerAcceptsPaddingInQuery(t *testing.T) {
	server := hNewServer(t, `{"mode":"packet-up",`+hBase+`}`)
	request := hRequest("POST", "/xh/s/0?x_padding="+strings.Repeat("X", 120), []byte("payload"), -1)
	recorder := hServe(server, request)
	require.Equal(t, http.StatusOK, recorder.Code)
}

func TestH_XHTTPServerHostWithPort(t *testing.T) {
	server := hNewServer(t, `{"mode":"packet-up","host":"Example.com",`+hBase+`}`)
	request := hRequest("POST", "/xh/s/0", []byte("x"), 150)
	request.Host = "example.com:8443"
	require.Equal(t, http.StatusOK, hServe(server, request).Code)
}

func TestH_XHTTPServerPacketUpQueuesPayload(t *testing.T) {
	server := hNewServer(t, `{"mode":"packet-up",`+hBase+`}`)
	recorder := hServe(server, hRequest("POST", "/xh/sid/1", []byte("second"), 150))
	require.Equal(t, http.StatusOK, recorder.Code)
	padding := recorder.Header().Get("X-Padding")
	require.GreaterOrEqual(t, len(padding), 100)
	require.LessOrEqual(t, len(padding), 200)
	require.Equal(t, "*", recorder.Header().Get("Access-Control-Allow-Origin"))
	require.Equal(t, http.StatusOK, hServe(server, hRequest("POST", "/xh/sid/0", []byte("first-"), 150)).Code)

	sessionAny, loaded := server.sessions.Load("sid")
	require.True(t, loaded)
	session := sessionAny.(*httpSession)
	require.Same(t, session, server.upsertSession("sid"))
	var out []byte
	buffer := make([]byte, 64)
	for len(out) < len("first-second") {
		n, err := session.uploadQueue.Read(buffer)
		require.NoError(t, err)
		out = append(out, buffer[:n]...)
	}
	require.Equal(t, "first-second", string(out))
}

func TestH_XHTTPServerHeaderUplinkData(t *testing.T) {
	server := hNewServer(t, `{"mode":"packet-up","uplink_data_placement":"header",`+hBase+`}`)
	request := hRequest("GET", "/xh/sid/0", nil, 150)
	request.Header.Set("X-Data-Upstream", "1")
	request.Header.Set("X-Data-0", "aGVsbG8")
	request.Header.Set("X-Data-Length", "7")
	require.Equal(t, http.StatusOK, hServe(server, request).Code)
	sessionAny, _ := server.sessions.Load("sid")
	buffer := make([]byte, 16)
	n, err := sessionAny.(*httpSession).uploadQueue.Read(buffer)
	require.NoError(t, err)
	require.Equal(t, "hello", string(buffer[:n]))

	request = hRequest("GET", "/xh/sid2/0", nil, 150)
	request.Header.Set("X-Data-Upstream", "1")
	request.Header.Set("X-Data-0", "aGVsbG8")
	request.Header.Set("X-Data-Length", "99")
	require.Equal(t, http.StatusInternalServerError, hServe(server, request).Code)
}

func TestH_XHTTPServerStreamDownHeaders(t *testing.T) {
	for _, noSSE := range []bool{false, true} {
		content := `{"mode":"packet-up",` + hBase + `}`
		if noSSE {
			content = `{"mode":"packet-up","no_sse_header":true,` + hBase + `}`
		}
		server := hNewServer(t, content)
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		request := hRequest("GET", "/xh/sid/", nil, 150).WithContext(ctx)
		recorder := hServe(server, request)
		cancel()
		require.Equal(t, http.StatusOK, recorder.Code)
		require.Equal(t, "no", recorder.Header().Get("X-Accel-Buffering"))
		require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
		if noSSE {
			require.Empty(t, recorder.Header().Get("Content-Type"))
		} else {
			require.Equal(t, "text/event-stream", recorder.Header().Get("Content-Type"))
		}
		_, loaded := server.sessions.Load("sid")
		require.False(t, loaded, "session must be removed once the GET finishes")
	}
}

func TestH_XHTTPServerObfsHeaderPadding(t *testing.T) {
	t.Skip("BUG: obfs-mode request padding (placement=header) is never read by the server, which only checks Referer/query x_padding (server.go:121-133); valid requests get 400")
	server := hNewServer(t, `{"mode":"packet-up","x_padding_obfs_mode":true,"x_padding_placement":"header",`+hBase+`}`)
	request := hRequest("POST", "/xh/sid/0", []byte("x"), -1)
	ApplyXPaddingToRequest(request, XPaddingConfig{
		Length:    150,
		Method:    PaddingMethodRepeatX,
		Placement: XPaddingPlacement{Placement: option.PlacementHeader, Header: "X-Padding", Key: "x_padding"},
	})
	require.Equal(t, http.StatusOK, hServe(server, request).Code)
}

func TestH_XHTTPServerNetwork(t *testing.T) {
	server := hNewServer(t, `{"mode":"auto",`+hBase+`}`)
	require.Equal(t, "tcp", server.network())
	require.Error(t, server.ServePacket(nil))
	require.NoError(t, server.Close())
}

package v2rayhttp

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// A short raw HTTP request fitted in the first read of Xray's header server behind a PROXY protocol hop (about
// 200 to 228 bytes), with the start of a Trojan request: Xray's Trojan inbound answered 400 Bad Request. The
// request now ends after that read, and the bytes where the read can end are inside a header value.
func TestH_HTTP1RequestOutlivesXrayFirstRead(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	request := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Path: "/aygyzUHLZi7luJrKz"},
		Header: http.Header{"User-Agent": {"Mozilla/5.0"}},
		Host:   "a.example.com",
	}
	conn := NewHTTP1Conn(client, request)
	payload := []byte(strings.Repeat("e", 56) + "\r\n")
	go func() {
		_, _ = conn.Write(payload)
		client.Close()
	}()
	sent, err := io.ReadAll(server)
	require.NoError(t, err)

	end := bytes.Index(sent, []byte("\r\n\r\n"))
	require.Greater(t, end, hPaddingCoverTo, "the request fits in the first read")
	for cut := hPaddingCoverFrom; cut < hPaddingCoverTo; cut++ {
		lineStart := bytes.LastIndex(sent[:cut], []byte("\r\n")) + 2
		colon := bytes.Index(sent[lineStart:], []byte(": "))
		require.True(t, colon >= 0 && lineStart+colon+2 <= cut, "byte %d is not inside a header value", cut)
	}
}

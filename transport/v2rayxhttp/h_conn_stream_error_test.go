package xhttp

import (
	"errors"
	"io"
	"net"
	"testing"

	"golang.org/x/net/http2"
)

type streamErrorReadWriter struct{ err error }

func (r streamErrorReadWriter) Read([]byte) (int, error)  { return 0, r.err }
func (r streamErrorReadWriter) Write([]byte) (int, error) { return 0, r.err }
func (streamErrorReadWriter) Close() error                { return nil }

// An HTTP/2 stream error of the XHTTP stream must not come out of splitConn bare: HTTP/2 over the
// conn (an HTTPS URL test through the proxy) takes a bare one for its own frame's stream error and
// keeps reading the sticky error from TLS, spinning a core forever.
func TestH_XHTTPSplitConnWrapsStreamError(t *testing.T) {
	reset := http2.StreamError{StreamID: 3, Code: http2.ErrCodeProtocol}
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{name: "protocol_error", err: reset, want: reset},
		{name: "cancel", err: http2.StreamError{StreamID: 3, Code: http2.ErrCodeCancel}, want: net.ErrClosed},
		{name: "unexpected_eof", err: io.ErrUnexpectedEOF, want: io.EOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			rw := streamErrorReadWriter{err: test.err}
			conn := &splitConn{writer: rw, reader: rw}
			_, readErr := conn.Read(make([]byte, 1))
			_, writeErr := conn.Write([]byte{1})
			for _, err := range []error{readErr, writeErr} {
				if _, bare := err.(http2.StreamError); bare {
					t.Fatal("splitConn leaked a bare HTTP/2 stream error")
				}
				if !errors.Is(err, test.want) {
					t.Fatalf("error = %v, want %v", err, test.want)
				}
			}
		})
	}
}

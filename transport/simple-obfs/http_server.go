package obfs

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// HTTPObfsServer is the server-side simple-obfs HTTP implementation.
// It strips the client's HTTP upgrade request and replies with HTTP 101.
type HTTPObfsServer struct {
	net.Conn
	hosts         []string //H obfs_host; empty allows any
	buf           []byte
	bio           *bufio.Reader
	recorder      *recordingReader
	offset        int
	firstRequest  bool
	firstResponse bool
}

// recordingReader keeps a copy of what it reads until stopped, so that a request
// that turns out not to be simple-obfs can be replayed with everything bufio read ahead.
type recordingReader struct {
	io.Reader
	recorded []byte
	stopped  bool
}

func (r *recordingReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	if !r.stopped {
		r.recorded = append(r.recorded, b[:n]...)
	}
	return n, err
}

// handshake reads and checks the client's upgrade request. It returns every byte
// it read, so that a connection that is not simple-obfs can be replayed to a fallback server.
func (hos *HTTPObfsServer) handshake() ([]byte, error) {
	hos.firstRequest = false
	hos.recorder = &recordingReader{Reader: hos.Conn}
	bio := bufio.NewReader(hos.recorder)
	prefix, err := bio.Peek(4)
	if err != nil {
		return hos.recorder.recorded, err
	}
	if string(prefix) != "GET " {
		return hos.recorder.recorded, ErrNotObfs
	}
	req, err := http.ReadRequest(bio)
	if err != nil {
		return hos.recorder.recorded, ErrNotObfs
	}
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") ||
		!strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade") {
		return hos.recorder.recorded, ErrNotObfs
	}
	if !hostAllowed(req.Host, hos.hosts) { //H obfs_host
		return hos.recorder.recorded, ErrNotObfs
	}
	body, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		return hos.recorder.recorded, err
	}
	hos.recorder.stopped = true
	hos.recorder.recorded = nil
	if len(body) > 0 {
		hos.buf = body
	}
	hos.bio = bio
	return nil, nil
}

func (hos *HTTPObfsServer) Read(b []byte) (int, error) {
	if hos.firstRequest {
		if _, err := hos.handshake(); err != nil {
			return 0, err
		}
	}

	if hos.buf != nil {
		n := copy(b, hos.buf[hos.offset:])
		hos.offset += n
		if hos.offset == len(hos.buf) {
			hos.offset = 0
			hos.buf = nil
		}
		return n, nil
	}

	return hos.bio.Read(b)
}

const httpResponseTemplate = "HTTP/1.1 101 Switching Protocols\r\n" +
	"Server: nginx/1.%d.%d\r\n" +
	"Date: %s\r\n" +
	"Upgrade: websocket\r\n" +
	"Connection: Upgrade\r\n" +
	"Sec-WebSocket-Accept: %s\r\n" +
	"\r\n"

func (hos *HTTPObfsServer) Write(b []byte) (int, error) {
	if hos.firstResponse {
		randBytes := make([]byte, 16)
		rand.Read(randBytes)
		date := time.Now().UTC().Format(http.TimeFormat) // GMT, as nginx sends it
		resp := fmt.Sprintf(httpResponseTemplate, randInt()%11, randInt()%12, date, base64.URLEncoding.EncodeToString(randBytes))
		if _, err := hos.Conn.Write([]byte(resp)); err != nil {
			return 0, err
		}
		hos.firstResponse = false
	}
	return hos.Conn.Write(b)
}

func (hos *HTTPObfsServer) Upstream() any {
	return hos.Conn
}

// NewHTTPObfsServer wraps conn with server-side HTTP obfs.
func NewHTTPObfsServer(conn net.Conn) net.Conn {
	return &HTTPObfsServer{
		Conn:          conn,
		firstRequest:  true,
		firstResponse: true,
	}
}

// randInt returns a pseudo-random non-negative integer.
func randInt() int {
	b := make([]byte, 1)
	rand.Read(b)
	return int(b[0])
}

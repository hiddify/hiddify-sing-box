package obfs

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// HTTPObfsServer is the server-side simple-obfs HTTP implementation.
// It strips the client's HTTP upgrade request and replies with HTTP 101.
type HTTPObfsServer struct {
	net.Conn
	buf           []byte
	bio           *bufio.Reader
	offset        int
	firstRequest  bool
	firstResponse bool
}

func (hos *HTTPObfsServer) Read(b []byte) (int, error) {
	if hos.buf != nil {
		n := copy(b, hos.buf[hos.offset:])
		hos.offset += n
		if hos.offset == len(hos.buf) {
			hos.offset = 0
			hos.buf = nil
		}
		return n, nil
	}

	if hos.firstRequest {
		bio := bufio.NewReader(hos.Conn)
		req, err := http.ReadRequest(bio)
		if err != nil {
			return 0, err
		}
		if req.Method != "GET" || req.Header.Get("Connection") != "Upgrade" {
			return 0, io.EOF
		}

		body, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return 0, err
		}
		n := copy(b, body)
		if n < len(body) {
			hos.buf = body
			hos.offset = n
		}
		hos.bio = bio
		hos.firstRequest = false
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
		date := time.Now().Format(time.RFC1123)
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

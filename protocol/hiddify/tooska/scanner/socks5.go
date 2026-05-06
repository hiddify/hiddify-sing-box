package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	socksTLSHost = "www.google.com"
	socksTLSPort = 443
)

var socksTLSRequest = []byte("GET /generate_204 HTTP/1.1\r\n" +
	"Host: www.google.com\r\n" +
	"User-Agent: Mozilla/5.0\r\n" +
	"Connection: close\r\n\r\n")

var socksTLSConfig = &tls.Config{
	ServerName: socksTLSHost,
	MinVersion: tls.VersionTLS12,
	NextProtos: []string{"http/1.1"},
}

func probeSOCKS5(ctx context.Context, cfg Config, ep Endpoint) (latencyMS int64, err error) {
	start := time.Now()

	tConnect := durationFraction(cfg.ProbeTimeout, 0.40)
	tTLS := durationFraction(cfg.ProbeTimeout, 0.40)
	tData := durationFraction(cfg.ProbeTimeout, 0.20)

	conn, err := dialFast(ctx, ep, cfg.DialTimeout)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	release := armCancel(ctx, conn)
	defer release()

	_ = conn.SetDeadline(time.Now().Add(tConnect))
	if _, err := conn.Write(socks5Greeting); err != nil {
		return 0, fmt.Errorf("greet: %w", err)
	}
	authReply := make([]byte, 2)
	if _, err := io.ReadFull(conn, authReply); err != nil {
		return 0, fmt.Errorf("greet read: %w", err)
	}
	if authReply[0] != 0x05 || authReply[1] != 0x00 {
		return 0, errors.New("socks5 auth method rejected")
	}

	host := []byte(socksTLSHost)
	req := make([]byte, 0, 7+len(host))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(host)))
	req = append(req, host...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(socksTLSPort))
	req = append(req, port...)
	if _, err := conn.Write(req); err != nil {
		return 0, fmt.Errorf("connect: %w", err)
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return 0, fmt.Errorf("connect head: %w", err)
	}
	if head[0] != 0x05 {
		return 0, fmt.Errorf("bad version 0x%02x", head[0])
	}
	if head[1] != 0x00 {
		return 0, fmt.Errorf("connect rep=0x%02x", head[1])
	}

	switch head[3] {
	case 0x01:
		if _, err := io.ReadFull(conn, make([]byte, 4+2)); err != nil {
			return 0, fmt.Errorf("bnd v4: %w", err)
		}
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return 0, fmt.Errorf("bnd dom-len: %w", err)
		}
		if _, err := io.ReadFull(conn, make([]byte, int(l[0])+2)); err != nil {
			return 0, fmt.Errorf("bnd dom: %w", err)
		}
	case 0x04:
		if _, err := io.ReadFull(conn, make([]byte, 16+2)); err != nil {
			return 0, fmt.Errorf("bnd v6: %w", err)
		}
	default:
		return 0, fmt.Errorf("unsupported atyp 0x%02x", head[3])
	}

	_ = conn.SetDeadline(time.Now().Add(tTLS))
	tlsConn := tls.Client(conn, socksTLSConfig)
	hsCtx, hsCancel := context.WithTimeout(ctx, tTLS)
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		hsCancel()
		return 0, fmt.Errorf("tls handshake: %w", err)
	}
	hsCancel()

	_ = tlsConn.SetDeadline(time.Now().Add(tData))
	if _, err := tlsConn.Write(socksTLSRequest); err != nil {
		return 0, fmt.Errorf("inner write: %w", err)
	}
	resp, err := readBounded(tlsConn, 256)
	if err != nil && len(resp) == 0 {
		return 0, fmt.Errorf("inner read: %w", err)
	}
	if !bytes.HasPrefix(resp, []byte("HTTP/1.1 204")) &&
		!bytes.HasPrefix(resp, []byte("HTTP/1.0 204")) &&
		!bytes.HasPrefix(resp, []byte("HTTP/1.1 200")) &&
		!bytes.HasPrefix(resp, []byte("HTTP/1.0 200")) {
		return 0, fmt.Errorf("inner status not 2xx: %q", firstLineBytes(resp))
	}

	return time.Since(start).Milliseconds(), nil
}

func durationFraction(d time.Duration, frac float64) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(float64(d) * frac)
}

func firstLineBytes(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return string(bytes.TrimRight(b[:i], "\r"))
	}
	return string(b)
}

func readBounded(r io.Reader, limit int) ([]byte, error) {
	buf := make([]byte, 0, limit)
	chunk := make([]byte, 512)
	for len(buf) < limit {
		n, err := r.Read(chunk)
		if n > 0 {
			remaining := limit - len(buf)
			if n > remaining {
				n = remaining
			}
			buf = append(buf, chunk[:n]...)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return buf, nil
			}
			return buf, err
		}
	}
	return buf, nil
}

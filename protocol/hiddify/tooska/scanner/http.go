package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"
)

const httpReadLimit = 8192

const (
	httpProbeHost = "example.com"
	httpProbePath = "/"
)

var httpSignature = []byte("Example Domain")

var httpSoftSignatures = [][]byte{
	[]byte("cf-ray:"),
	[]byte("server: cloudflare"),
	[]byte("x-cache:"),
}

func probeHTTP(ctx context.Context, cfg Config, ep Endpoint) (latencyMS int64, err error) {
	start := time.Now()

	conn, err := dialFast(ctx, ep, cfg.DialTimeout)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	release := armCancel(ctx, conn)
	defer release()

	_ = conn.SetDeadline(time.Now().Add(cfg.ProbeTimeout))
	req := buildHTTPProxyRequest(cfg.UserAgent)
	if _, err := conn.Write(req); err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}

	buf, err := readBounded(conn, httpReadLimit)
	if err != nil && len(buf) == 0 {
		return 0, fmt.Errorf("read: %w", err)
	}
	if len(buf) == 0 {
		return 0, errors.New("empty response")
	}

	if bytes.Contains(buf, httpSignature) {
		return time.Since(start).Milliseconds(), nil
	}

	is200 := bytes.HasPrefix(buf, []byte("HTTP/1.1 200")) || bytes.HasPrefix(buf, []byte("HTTP/1.0 200"))
	if is200 {
		lowerBuf := bytes.ToLower(buf)
		for _, sig := range httpSoftSignatures {
			if bytes.Contains(lowerBuf, sig) {
				return time.Since(start).Milliseconds(), nil
			}
		}
	}

	return 0, fmt.Errorf("response rejected (no signature): %q", firstLineBytes(buf))
}

func buildHTTPProxyRequest(ua string) []byte {
	return []byte(
		"GET http://" + httpProbeHost + httpProbePath + " HTTP/1.1\r\n" +
			"Host: " + httpProbeHost + "\r\n" +
			"User-Agent: " + ua + "\r\n" +
			"Accept: text/html\r\n" +
			"Accept-Encoding: identity\r\n" +
			"Connection: close\r\n\r\n",
	)
}

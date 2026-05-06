package scanner

import (
	"bytes"
	"context"
	"net"
	"time"
)

type fingerprintVerdict int

const (
	fpTLS fingerprintVerdict = iota
	fpSOCKS5
	fpHTTP
	fpAmbiguous
)

var socks5Greeting = []byte{0x05, 0x01, 0x00}

func fingerprint(ctx context.Context, conn net.Conn, timeout time.Duration) fingerprintVerdict {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(socks5Greeting); err != nil {
		return fpAmbiguous
	}
	buf := make([]byte, 8)
	n, _ := conn.Read(buf)
	return classifyFingerprint(buf[:n])
}

func classifyFingerprint(buf []byte) fingerprintVerdict {
	if len(buf) >= 2 && buf[0] == 0x05 && buf[1] == 0x00 {
		return fpSOCKS5
	}
	if bytes.HasPrefix(buf, []byte("HTTP/")) {
		return fpHTTP
	}
	if len(buf) >= 1 && (buf[0] == 0x15 || buf[0] == 0x16) {
		return fpTLS
	}
	return fpAmbiguous
}

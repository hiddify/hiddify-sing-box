package obfs

import (
	"net"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// ErrNotObfs is returned by ServerHandshake when the first request on a connection
// is not a simple-obfs request, such as a real browser or an active probe.
var ErrNotObfs = E.New("not a simple-obfs request")

// ServerHandshake reads and checks the client's first request for the given obfs mode
// ("http" or "tls") and returns the connection to read the payload from.
// On failure it also returns every byte it read from conn, so the caller can replay
// them to a fallback server; the error is ErrNotObfs when the request is not simple-obfs.
//
// With hosts, the request's HTTP Host or TLS server name must be one of them (case-insensitive);
// any other is treated as not simple-obfs.
func ServerHandshake(conn net.Conn, mode string, hosts ...string) (net.Conn, []byte, error) {
	switch mode {
	case "http":
		server := &HTTPObfsServer{Conn: conn, firstRequest: true, firstResponse: true, hosts: hosts}
		if cached, err := server.handshake(); err != nil {
			return nil, cached, err
		}
		return server, nil, nil
	case "tls":
		server := &TLSObfsServer{Conn: conn, firstResponse: true, hosts: hosts}
		if cached, err := server.handshake(); err != nil {
			return nil, cached, err
		}
		return server, nil, nil
	default:
		return nil, nil, E.New("unknown obfs mode: ", mode)
	}
}

// hostAllowed reports whether host, without a port, is one of hosts; no hosts allows any.
func hostAllowed(host string, hosts []string) bool {
	if len(hosts) == 0 {
		return true
	}
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	for _, allowed := range hosts {
		if strings.EqualFold(strings.TrimSpace(allowed), host) {
			return true
		}
	}
	return false
}

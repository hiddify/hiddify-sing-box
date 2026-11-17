package xhttp

import (
	"net/http"
	"strings"

	"github.com/sagernet/sing-box/common/xray/net"
	"github.com/sagernet/sing-box/common/xray/signal/done"
)

type httpSession struct {
	uploadQueue *uploadQueue
	// for as long as the GET request is not opened by the client, this will be
	// open ("undone"), and the session may be expired within a certain TTL.
	// after the client connects, this becomes "done" and the session lives as
	// long as the GET request.
	isFullyConnected *done.Instance
}

func parseXForwardedFor(header http.Header) []net.Address {
	xff := header.Get("X-Forwarded-For")
	if xff == "" {
		return nil
	}
	list := strings.Split(xff, ",")
	addrs := make([]net.Address, 0, len(list))
	for _, proxy := range list {
		addrs = append(addrs, net.ParseAddress(proxy))
	}
	return addrs
}

func isValidHTTPHost(request string, config string) bool {
	// H: a Host with a colon was split as host:port, which a bracketed IPv6 address without a
	// port is not: "[2001:db8::1]", what a client sends for the host 2001:db8::1 on the default
	// port, never matched, and the server answered 404 to every request
	return hHostName(request) == hHostName(config) //H
}

// hHostName is the host of an HTTP Host value, in lower case, without its port and without the
// brackets of an IPv6 address. //H
func hHostName(value string) string {
	value = strings.ToLower(value)
	if host, _, err := net.SplitHostPort(value); err == nil {
		return host
	}
	return strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
}

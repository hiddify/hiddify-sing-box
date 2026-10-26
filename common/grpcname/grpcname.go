// Package grpcname reads a gRPC transport's service_name the way Xray does.
package grpcname

import (
	"net/url"
	"strings"
)

// Names returns the service and stream names that make up the method path of service_name.
//
// A name starting with "/" is a custom path, "/<service>/<stream>": "/my/path/Tun" is service
// "my/path" and stream "Tun". Xray's server form "/<service>/<stream>|<multi stream>" also names
// the stream of its multi mode, which sing-box does not use, so the part after "|" is ignored.
// Any other name is the service, and the stream is "Tun". Every path segment is escaped with
// url.PathEscape, as in Xray.
func Names(serviceName string) (service string, stream string) {
	if !strings.HasPrefix(serviceName, "/") {
		return url.PathEscape(serviceName), "Tun"
	}
	lastIndex := strings.LastIndex(serviceName, "/")
	serviceIndex := max(lastIndex, 1)
	serviceParts := strings.Split(serviceName[1:serviceIndex], "/")
	for i := range serviceParts {
		serviceParts[i] = url.PathEscape(serviceParts[i])
	}
	streamNames := strings.Split(serviceName[lastIndex+1:], "|")
	return strings.Join(serviceParts, "/"), url.PathEscape(streamNames[0])
}

// Path returns the method path of service_name as sent on the wire, "/<service>/<stream>".
func Path(serviceName string) string {
	service, stream := Names(serviceName)
	return "/" + service + "/" + stream
}

// UnescapedPath returns Path decoded, as net/http keeps it in URL.Path.
func UnescapedPath(serviceName string) string {
	path := Path(serviceName)
	unescaped, err := url.PathUnescape(path)
	if err != nil {
		return path
	}
	return unescaped
}

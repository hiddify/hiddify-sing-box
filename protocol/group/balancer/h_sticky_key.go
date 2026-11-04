package balancer

import (
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
)

// What a connection sticks to a member by (sticky_hash), for the pool and sticky-sessions.
const (
	stickyHashProcess     = "process"
	stickyHashDomain      = "domain"
	stickyHashSourceIP    = "source_ip"
	stickyHashDestIP      = "dest_ip"
	stickyHashDestPort    = "dest_port"
	stickyHashNone        = "none"
	stickyKeyFieldDivider = "|"
)

var (
	defaultStickyHash        = []string{stickyHashProcess, stickyHashDomain}  // the pool's
	defaultStickySessionHash = []string{stickyHashSourceIP, stickyHashDomain} // sticky-sessions', as before the option
)

// parseStickyHash checks the sticky_hash fields, fallback when none are given; "none" alone gives
// nil: nothing to stick by.
func parseStickyHash(fields []string, fallback []string) ([]string, error) {
	if len(fields) == 0 {
		return fallback, nil
	}
	for _, field := range fields {
		switch field {
		case stickyHashProcess, stickyHashDomain, stickyHashSourceIP, stickyHashDestIP, stickyHashDestPort:
		case stickyHashNone:
			if len(fields) > 1 {
				return nil, E.New(`sticky_hash "none" cannot be combined with other fields`)
			}
			return nil, nil
		default:
			return nil, E.New("unknown sticky_hash field: ", field)
		}
	}
	return fields, nil
}

// stickyKey is what a connection sticks by: the fields named, in order.
func stickyKey(metadata *adapter.InboundContext, fields []string) string {
	var builder strings.Builder
	for _, field := range fields {
		switch field {
		case stickyHashProcess:
			if metadata.ProcessInfo != nil {
				if len(metadata.ProcessInfo.ProcessPaths) > 0 {
					builder.WriteString(metadata.ProcessInfo.ProcessPaths[0])
				} else if len(metadata.ProcessInfo.PackageNames) > 0 {
					builder.WriteString(metadata.ProcessInfo.PackageNames[0])
				}
			}
		case stickyHashDomain:
			builder.WriteString(getKey(metadata))
		case stickyHashSourceIP:
			builder.WriteString(metadata.Source.Addr.String())
		case stickyHashDestIP:
			if len(metadata.DestinationAddresses) > 0 {
				builder.WriteString(metadata.DestinationAddresses[0].String())
			} else {
				builder.WriteString(metadata.Destination.Addr.String())
			}
		case stickyHashDestPort:
			builder.WriteString(strconv.Itoa(int(metadata.Destination.Port)))
		}
		builder.WriteString(stickyKeyFieldDivider)
	}
	return builder.String()
}

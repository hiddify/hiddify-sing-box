package awg

import (
	"regexp"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// masqueradeDomain is a plain DNS name: the domain is written inside an i-packet tag, so nothing
// that could end the tag or start another may pass.
var masqueradeDomain = regexp.MustCompile(`^(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

// masqueradePacket turns the ip/id/ib masquerade settings into the i1 tag: for quic, a fresh QUIC
// Initial for the domain before every handshake. Empty when masquerade is not set.
func masqueradePacket(awg option.AwgOptions) (string, error) {
	if awg.IP == "" {
		if awg.ID != "" || awg.IB != "" {
			return "", E.New("awg: id and ib need ip")
		}
		return "", nil
	}
	if awg.I1 != "" {
		return "", E.New("awg: ip/id/ib replace i1, set only one of them")
	}
	switch strings.ToLower(awg.IP) {
	case "quic":
	case "dns", "stun", "sip":
		return "", E.New("awg: masquerade ", awg.IP, " is not supported, only quic")
	default:
		return "", E.New("awg: unknown masquerade protocol: ", awg.IP)
	}
	switch strings.ToLower(awg.IB) {
	case "", "chrome", "firefox", "curl":
	default:
		return "", E.New("awg: unknown masquerade client profile: ", awg.IB)
	}
	if len(awg.ID) > 253 || !masqueradeDomain.MatchString(awg.ID) {
		return "", E.New("awg: quic masquerade needs id, a domain name: ", awg.ID)
	}
	return "<qi " + strings.ToLower(awg.ID) + ">", nil
}

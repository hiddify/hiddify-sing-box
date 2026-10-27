package dialer

import (
	"encoding/json"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// H: the dialer's tls_fragment is kept for existing configs and applied as a finalmask fragment
// mask (Xray's fragment): size is the record length range, sleep the delay between records,
// method "tlsHello" (the default) fragments the ClientHello and "range" the packets in range.

// withTLSFragment returns finalMask with the mask for options in front, so it wraps the others
// and sees the bytes the TLS stack writes.
func withTLSFragment(finalMask *option.FinalMaskOptions, options option.TLSFragmentOptions, tcpFastOpen bool) (*option.FinalMaskOptions, error) {
	if !options.Enabled {
		return finalMask, nil
	}
	if tcpFastOpen {
		return nil, E.New("TLS Fragmentation is not compatible with TCP Fast Open, set `tcp_fast_open` to `false` in your outbound if you intend to enable TLS fragmentation.")
	}
	size := options.Size
	if size == "" {
		size = "1-10"
	}
	sleep := options.Sleep
	if sleep == "" {
		sleep = "0"
	}
	packets := "tlshello"
	switch strings.ToLower(options.Method) {
	case "", "tlshello":
	case "range":
		if options.Range == "" {
			return nil, E.New("TLS fragment `range` method needs a `range`, such as \"1-3\"")
		}
		packets = options.Range
	default:
		return nil, E.New("unknown TLS fragment `method`: ", options.Method)
	}
	settings, err := json.Marshal(map[string]string{"packets": packets, "length": size, "delay": sleep})
	if err != nil {
		return nil, err
	}
	merged := option.FinalMaskOptions{}
	if finalMask != nil {
		merged = *finalMask
	}
	merged.TCP = append([]option.FinalMaskItem{{Type: "fragment", Settings: settings}}, merged.TCP...)
	return &merged, nil
}

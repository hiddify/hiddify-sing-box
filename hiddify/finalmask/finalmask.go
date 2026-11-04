// Package finalmask applies Xray-core finalmask masks (fragment, noise, header-custom, sudoku,
// salamander, xdns, udphop, merge, oob, ...) to the connections a sing-box dialer opens. The masks
// themselves are Xray-core's, except merge and oob; this package parses the Xray JSON form and
// dials through the masks.
package finalmask

import (
	"encoding/json"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	xfinalmask "github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/finalmask/xdns"
	"google.golang.org/protobuf/proto"
)

// Masks holds the built masks of one dialer, in the order of the options: the first tcp mask is
// the outermost, the last one is next to the socket.
type Masks struct {
	tcp []xfinalmask.TCPMask
	udp []xfinalmask.UDPMask
}

// Build parses and validates options; it returns nil when there is nothing to apply.
func Build(options *option.FinalMaskOptions) (*Masks, error) {
	if options.IsEmpty() {
		return nil, nil
	}
	masks := &Masks{}
	for i, item := range options.TCP {
		config, err := buildMask(item, true)
		if err != nil {
			return nil, E.Cause(err, "finalmask.tcp[", i, "] ", item.Type)
		}
		mask, ok := config.(xfinalmask.TCPMask)
		if !ok {
			return nil, E.New("finalmask.tcp[", i, "]: ", item.Type, " is not a tcp mask")
		}
		masks.tcp = append(masks.tcp, mask)
	}
	for i, item := range options.UDP {
		config, err := buildMask(item, false)
		if err != nil {
			return nil, E.Cause(err, "finalmask.udp[", i, "] ", item.Type)
		}
		mask, ok := config.(xfinalmask.UDPMask)
		if !ok {
			return nil, E.New("finalmask.udp[", i, "]: ", item.Type, " is not a udp mask")
		}
		masks.udp = append(masks.udp, mask)
	}
	if last := len(masks.udp) - 1; last >= 0 {
		if config, isXDNS := masks.udp[last].(*xdns.Config); isXDNS {
			masks.udp[last] = &selfDialingXDNS{config}
		}
	}
	return masks, nil
}

// selfDialingXDNS is xdns next to the socket. It sends through its resolvers and ignores the
// socket it is given, which Xray dials to the destination anyway and never closes; HandleDial
// tells Xray not to dial it.
type selfDialingXDNS struct {
	*xdns.Config
}

func (*selfDialingXDNS) HandleDial() {}

// HasTCP and HasUDP tell whether there is a mask of that kind.
func (m *Masks) HasTCP() bool { return m != nil && len(m.tcp) > 0 }
func (m *Masks) HasUDP() bool { return m != nil && len(m.udp) > 0 }

// buildable is a mask's settings whose Build makes an Xray mask config.
type buildable interface {
	Build() (proto.Message, error)
}

// tcpmaskBuildable is the settings of a mask implemented here rather than in Xray-core (merge,
// oob): it builds the mask itself.
type tcpmaskBuildable interface {
	BuildTcpmask() (xfinalmask.TCPMask, error)
}

// newMaskConfig mirrors Xray's tcpmaskLoader / udpmaskLoader; it returns a buildable or a
// tcpmaskBuildable.
func newMaskConfig(maskType string, tcp bool) any {
	if tcp {
		switch maskType {
		case "header-custom":
			return new(HeaderCustomTCP)
		case "fragment":
			return new(FragmentMask)
		case "merge":
			return new(MergeMask)
		case "mirage":
			return new(MirageMask)
		case "oob":
			return new(OOBMask)
		case "sudoku":
			return new(Sudoku)
		case "xmc":
			return new(XMC)
		}
		return nil
	}
	switch maskType {
	case "header-custom":
		return new(HeaderCustomUDP)
	case "mkcp-legacy":
		return new(MkcpLegacy)
	case "noise":
		return new(NoiseMask)
	case "salamander":
		return new(Salamander)
	case "sudoku":
		return new(Sudoku)
	case "xdns":
		return new(xdnsSettings)
	case "xicmp":
		return new(Xicmp)
	case "realm":
		return new(Realm)
	case "udphop":
		return new(UDPHop)
	}
	return nil
}

// buildMask returns the mask config, which the caller asserts to an Xray TCPMask or UDPMask.
func buildMask(item option.FinalMaskItem, tcp bool) (any, error) {
	config := newMaskConfig(strings.ToLower(item.Type), tcp)
	if config == nil {
		return nil, E.New("unknown mask type")
	}
	settings := []byte(item.Settings)
	if len(settings) == 0 || string(settings) == "null" {
		settings = []byte("{}")
	}
	if err := json.Unmarshal(settings, config); err != nil {
		return nil, E.Cause(err, "parse settings")
	}
	switch config := config.(type) {
	case tcpmaskBuildable:
		return config.BuildTcpmask()
	case buildable:
		return config.Build()
	}
	return nil, E.New("unknown mask type")
}

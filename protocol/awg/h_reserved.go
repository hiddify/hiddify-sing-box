package awg

import (
	"github.com/sagernet/sing-box/option"
	awgtransport "github.com/sagernet/sing-box/transport/awg"
	E "github.com/sagernet/sing/common/exceptions"
)

// reservedOptions are the reserved bytes of the endpoint's peer (WARP's client id), or nil.
func reservedOptions(options option.AwgEndpointOptions) (*awgtransport.Reserved, error) {
	var reserved *awgtransport.Reserved
	for i, peer := range options.Peers {
		if len(peer.Reserved) == 0 {
			continue
		}
		if len(peer.Reserved) != 3 {
			return nil, E.New("invalid reserved value for peer ", i, ", required 3 bytes, got ", len(peer.Reserved))
		}
		if reserved != nil || len(options.Peers) > 1 {
			return nil, E.New("reserved works with one peer only")
		}
		types, err := options.Awg.ReservedMessageTypes()
		if err != nil {
			return nil, err
		}
		reserved = &awgtransport.Reserved{Types: types}
		copy(reserved.Bytes[:], peer.Reserved)
	}
	return reserved, nil
}

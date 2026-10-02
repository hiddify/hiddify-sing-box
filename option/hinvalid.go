package option

import (
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
)

type HInvalidOptions struct {
	// InvalidConfig is the original options; json.RawMessage when the config failed to parse.
	InvalidConfig any `json:"-"`
	// OriginalType is the type declared in the config before it was replaced with hinvalid.
	OriginalType string `json:"-"`
	Err          error  `json:"-"`
}

func newInvalidOptions(originalType string, content []byte, err error) *HInvalidOptions {
	return &HInvalidOptions{
		InvalidConfig: json.RawMessage(append([]byte(nil), content...)),
		OriginalType:  originalType,
		Err:           err,
	}
}

// rawInvalidConfig returns the original JSON of an outbound/endpoint that failed to parse,
// so that re-marshalling a config keeps it unchanged.
func rawInvalidConfig(outboundType string, options any) ([]byte, bool) {
	if outboundType != C.TypeHInvalidConfig {
		return nil, false
	}
	invalidOptions, isInvalid := options.(*HInvalidOptions)
	if !isInvalid {
		return nil, false
	}
	raw, isRaw := invalidOptions.InvalidConfig.(json.RawMessage)
	return raw, isRaw
}

func labelInvalidOption(kind string, index int, tag string, options any) {
	invalidOptions, isInvalid := options.(*HInvalidOptions)
	if !isInvalid || invalidOptions.Err == nil {
		return
	}
	if tag == "" {
		tag = F.ToString(index)
	}
	invalidOptions.Err = E.Cause(invalidOptions.Err, kind, "[", index, ": ", tag, "]")
}

// labelInvalidOptions prefixes parse errors of invalid outbounds/endpoints with their index and tag,
// e.g. "outbounds[15: my-tag]: transport: ...".
func labelInvalidOptions(options *Options) {
	for i, outbound := range options.Outbounds {
		if outbound.Type == C.TypeHInvalidConfig {
			labelInvalidOption("outbounds", i, outbound.Tag, outbound.Options)
		}
	}
	for i, endpoint := range options.Endpoints {
		if endpoint.Type == C.TypeHInvalidConfig {
			labelInvalidOption("endpoints", i, endpoint.Tag, endpoint.Options)
		}
	}
}

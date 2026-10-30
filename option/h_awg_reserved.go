package option

import (
	"strconv"

	E "github.com/sagernet/sing/common/exceptions"
)

// ReservedMessageTypes are the first bytes of the four AmneziaWG message types. A peer's reserved
// bytes go into bytes 1–3 of these messages, where WireGuard has them, so the messages must start
// with their type and the types must fit in one byte: no s1–s4 padding in front, no encrypted
// headers, and h1–h4 single numbers up to 255.
func (o *AwgOptions) ReservedMessageTypes() ([4]byte, error) {
	var types [4]byte
	if o.S1 != 0 || o.S2 != 0 || o.S3 != 0 || o.S4 != 0 {
		return types, E.New("reserved needs s1–s4 to be 0: the padding would come where the reserved bytes go")
	}
	if o.HeaderProtectionKey != "" {
		return types, E.New("reserved does not work with header_protection_key")
	}
	for i, h := range []string{o.H1, o.H2, o.H3, o.H4} {
		value := uint64(i + 1)
		if h != "" {
			var err error
			value, err = strconv.ParseUint(h, 10, 32)
			if err != nil || value == 0 || value > 255 {
				return types, E.New("reserved needs h1–h4 to be numbers from 1 to 255, not ", strconv.Quote(h))
			}
		}
		types[i] = byte(value)
	}
	return types, nil
}

package awg

// Reserved are a peer's reserved bytes, which WARP reads as the client id: bytes 1–3 of each
// message, as in WireGuard. Messages start with their type, so a packet whose first byte is one of
// Types and whose bytes 1–3 are zero is a message; junk and i1–i5 packets almost never look so.
type Reserved struct {
	Bytes [3]byte
	Types [4]byte // the first bytes of h1–h4
}

func (r *Reserved) isMessage(packet []byte) bool {
	if len(packet) < 4 {
		return false
	}
	for _, t := range r.Types {
		if packet[0] == t {
			return true
		}
	}
	return false
}

// write puts the reserved bytes into an outgoing message.
func (r *Reserved) write(packet []byte) {
	if r != nil && r.isMessage(packet) && packet[1]|packet[2]|packet[3] == 0 {
		copy(packet[1:4], r.Bytes[:])
	}
}

// clear removes them from a received message: the server sends them back.
func (r *Reserved) clear(packet []byte) {
	if r != nil && r.isMessage(packet) {
		clear(packet[1:4])
	}
}

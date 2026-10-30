package wireguard

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestH_MTUProbeEchoRequest(t *testing.T) {
	for _, pair := range [][2]string{{"172.16.0.2", "1.1.1.1"}, {"2606:4700:110::2", "2606:4700:4700::1111"}} {
		source, target := netip.MustParseAddr(pair[0]), netip.MustParseAddr(pair[1])
		packet := buildEchoRequest(source, target, 0x1234, 7, 1280)
		if len(packet) != 1280 {
			t.Fatalf("size %d", len(packet))
		}
		if source.Is4() {
			if checksum(packet[:20], 0) != 0xffff || checksum(packet[20:], 0) != 0xffff {
				t.Errorf("IPv4 checksums do not verify")
			}
			continue
		}
		icmp := packet[40:]
		if checksum(icmp, uint32(checksum(packet[8:40], uint32(len(icmp))+58))) != 0xffff {
			t.Errorf("ICMPv6 checksum does not verify")
		}
	}
}

// Replies to the probes are taken out of what the device receives, and tell the probe; other
// packets, and replies to someone else's echo requests, go on.
func TestH_MTUProbeFilter(t *testing.T) {
	p := &mtuProber{id: 0x1234, pending: map[uint16]func(){}}
	answered := false
	p.pending[7] = func() { answered = true }
	reply := func(id uint16) []byte {
		packet := buildEchoRequest(netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("172.16.0.2"), id, 7, 100)
		packet[20] = 0 // echo reply
		return append(make([]byte, 16), packet...)
	}
	other := append(make([]byte, 16), 0x45, 0, 0, 40)
	bufs := p.filter([][]byte{other, reply(0x1234), reply(0x9999)}, 16)
	if len(bufs) != 2 || !answered {
		t.Fatalf("kept %d packets, answered %v", len(bufs), answered)
	}
	if binary.BigEndian.Uint16(bufs[1][16+24:]) != 0x9999 {
		t.Errorf("the wrong packet was taken")
	}
	var none *mtuProber
	if len(none.filter([][]byte{other}, 16)) != 1 {
		t.Errorf("no prober must keep every packet")
	}
}

// A packet larger than the lowered MTU is answered with "packet too big" instead of being sent.
func TestH_MTUProbeAnswerTooBig(t *testing.T) {
	router := newPeerRouter(DeviceOptions{MTU: 1280, Address: []netip.Prefix{netip.MustParsePrefix("172.16.0.2/32")}})
	defer router.close()
	router.memoryTun.UpdateMTU(1200)
	large := buildEchoRequest(netip.MustParseAddr("172.16.0.2"), netip.MustParseAddr("1.1.1.1"), 1, 1, 1280)
	if !router.answerTooBig(large) {
		t.Errorf("a 1280-byte packet passed an MTU of 1200")
	}
	small := buildEchoRequest(netip.MustParseAddr("172.16.0.2"), netip.MustParseAddr("1.1.1.1"), 1, 1, 1200)
	if router.answerTooBig(small) {
		t.Errorf("a 1200-byte packet was held back")
	}
}

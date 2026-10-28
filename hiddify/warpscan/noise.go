package warpscan

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/wireguard-go/hiddify"
)

// NoisePreset is noise that gets a WARP WireGuard handshake through on some networks, taken from
// WARP configs that work: Xray's random noise, and the special packets of AmneziaWG configs that
// make the start of the flow look like DNS, QUIC or SIP. The scanner tries them when no endpoint
// answers with the configured noise.
type NoisePreset struct {
	Name  string
	Noise hiddify.FakePacketOptions
}

// NoisePresets are tried in this order.
var NoisePresets = []NoisePreset{
	// Xray WARP: wnoise=random, wnoisecount=5, wpayloadsize=5-10, wnoisedelay=2-5
	{"xray-random", hiddify.FakePacketOptions{
		Mode: hiddify.NoiseModeRaw, Count: hiddify.Range{From: 5, To: 5}, Size: hiddify.Range{From: 5, To: 10}, Delay: hiddify.Range{From: 2, To: 5},
	}},
	// the start of a QUIC connection to www.google.com
	{"quic", hiddify.FakePacketOptions{
		Mode: hiddify.NoiseModeQUIC, Count: hiddify.Range{From: 2, To: 4}, Delay: hiddify.Range{From: 10, To: 30},
	}},
	// DNS queries for google.com (A, AAAA, HTTPS) with a random id, then junk
	{"dns-google", hiddify.FakePacketOptions{
		Packets: []string{
			"<r 2><b 0x0100000100000000000106676f6f676c6503636f6d00000100010000291000000000000000>",
			"<r 2><b 0x0100000100000000000106676f6f676c6503636f6d00001c00010000291000000000000000>",
			"<r 2><b 0x0100000100000000000106676f6f676c6503636f6d000041000100002904d0000000000000>",
		},
		Mode: hiddify.NoiseModeRaw, Count: hiddify.Range{From: 6, To: 6}, Size: hiddify.Range{From: 56, To: 160},
	}},
	// DNS queries for cloudflare.com (A, AAAA), then junk
	{"dns-cloudflare", hiddify.FakePacketOptions{
		Packets: []string{
			"<r 2><b 0x010000010000000000010a636c6f7564666c61726503636f6d000001000100002904d0000000000000>",
			"<r 2><b 0x010000010000000000010a636c6f7564666c61726503636f6d00001c000100002904d0000000000000>",
		},
		Mode: hiddify.NoiseModeRaw, Count: hiddify.Range{From: 9, To: 9}, Size: hiddify.Range{From: 81, To: 224},
	}},
	// DNS queries for www.cloudflare.com (A, AAAA), then junk
	{"dns-www-cloudflare", hiddify.FakePacketOptions{
		Packets: []string{
			"<r 2><b 0x01000001000000000001037777770a636c6f7564666c61726503636f6d000001000100002904d0000000000000>",
			"<r 2><b 0x01000001000000000001037777770a636c6f7564666c61726503636f6d00001c00010000291000000000000000>",
		},
		Mode: hiddify.NoiseModeRaw, Count: hiddify.Range{From: 6, To: 6}, Size: hiddify.Range{From: 43, To: 109},
	}},
	// a QUIC Initial and a short-header packet, then junk
	{"quic-mimic", hiddify.FakePacketOptions{
		Packets: []string{
			"<b 0xc30000000108f9a15db6b62f2eca00004102a86db502291b19dedd8bae27fc40532582410069940fe6d06c77e2312ea305087f47592f26b626d87812ce68e2ae6fdeac49f3137eb88bbaa540b7de515deb24733a58af75f03acc9dd676ac9a7ee96ea837006e8ed1a0d110adc21be31caf11d83a4ec7fbe330b944ee4b278783551a1090c8d38f142e9ee102442cd8e1210a5fcf727222887cf1d7b47c536083ed4644569bdeefa8388efbc80a7a86a7b526273f43d3063df805db3a5aa8d4a35e9a097f32bd1eb4770ce59a589694016d0d14baeb2c415b50b04d06f06e0ea0626678accbfda916a61d3f623cfd5286d8723a8c946ab1ab2541ef0a1c959e96bc9accbb5a598bc2722ffdc391c5c35ef91c06fb><r 934>",
			"<b 0x47e4a9a16a11ea385d><r 29>",
		},
		Mode: hiddify.NoiseModeRaw, Count: hiddify.Range{From: 4, To: 4}, Size: hiddify.Range{From: 60, To: 199},
	}},
	// a SIP INVITE and its "100 Trying" answer, then junk
	{"sip", hiddify.FakePacketOptions{
		Packets: []string{
			"<b 0x494e56495445207369703a6672616e6b407369702e6578616d706c652e6f7267205349502f322e300d0a5669613a205349502f322e302f55445020706331372e736f667470686f6e652e6578616d706c652e6e65743b6272616e63683d7a39684734624b446b366f536e54327839377a384279620d0a4d61782d466f7277617264733a2036390d0a546f3a204672616e6b203c7369703a6672616e6b407369702e6578616d706c652e6f72673e0d0a46726f6d3a204572696e203c7369703a6572696e40736f667470686f6e652e6578616d706c652e6e65743e3b7461673d35353531323230380d0a43616c6c2d49443a203238643533656365616438613430306240706331372e736f667470686f6e652e6578616d706c652e6e65740d0a435365713a2036363038333720494e564954450d0a436f6e746163743a203c7369703a6572696e40706331372e736f667470686f6e652e6578616d706c652e6e65743e0d0a436f6e74656e742d547970653a206170706c69636174696f6e2f7364700d0a436f6e74656e742d4c656e6774683a20300d0a0d0a>",
			"<b 0x5349502f322e302031303020547279696e670d0a5669613a205349502f322e302f55445020706331372e736f667470686f6e652e6578616d706c652e6e65743b6272616e63683d7a39684734624b446b366f536e54327839377a384279620d0a546f3a204672616e6b203c7369703a6672616e6b407369702e6578616d706c652e6f72673e0d0a46726f6d3a204572696e203c7369703a6572696e40736f667470686f6e652e6578616d706c652e6e65743e3b7461673d35353531323230380d0a43616c6c2d49443a203238643533656365616438613430306240706331372e736f667470686f6e652e6578616d706c652e6e65740d0a435365713a2036363038333720494e564954450d0a436f6e74656e742d4c656e6774683a20300d0a0d0a>",
		},
		Mode: hiddify.NoiseModeRaw, Count: hiddify.Range{From: 10, To: 10}, Size: hiddify.Range{From: 42, To: 224},
	}},
}

// NoisePresetByName returns the preset called name.
func NoisePresetByName(name string) (NoisePreset, bool) {
	for _, preset := range NoisePresets {
		if preset.Name == name {
			return preset, true
		}
	}
	return NoisePreset{}, false
}

// WireGuard is the preset as the noise of a WireGuard device.
func (p NoisePreset) WireGuard() hiddify.NoiseOptions {
	noise := p.Noise
	noise.Enabled = true
	return hiddify.NoiseOptions{FakePacket: noise}
}

// AWG is base (nil for none) with the preset as its junk and special packets: i1–i5 from the
// templates (a QUIC preset as <qi> packets) and jc/jmin/jmax from the junk.
func (p NoisePreset) AWG(base *option.AwgOptions) *option.AwgOptions {
	var awg option.AwgOptions
	if base != nil {
		awg = *base
	}
	packets := append([]string(nil), p.Noise.Packets...)
	awg.Jc, awg.Jmin, awg.Jmax = 0, 0, 0
	if p.Noise.Mode == hiddify.NoiseModeQUIC {
		for range p.Noise.Count.To {
			packets = append(packets, "<qi "+p.Noise.QUICServerName()+">")
		}
	} else {
		awg.Jc, awg.Jmin, awg.Jmax = int(p.Noise.Count.To), int(p.Noise.Size.From), int(p.Noise.Size.To)
	}
	special := []*string{&awg.I1, &awg.I2, &awg.I3, &awg.I4, &awg.I5}
	for i, field := range special {
		*field = ""
		if i < len(packets) {
			*field = packets[i]
		}
	}
	return &awg
}

// AWGProbeNoise is what an AmneziaWG device with awg sends before a handshake initiation, as
// noise for the scanner's probe: i1–i5, then jc junk packets of jmin to jmax bytes.
func AWGProbeNoise(awg *option.AwgOptions) hiddify.NoiseOptions {
	if awg == nil {
		return hiddify.NoiseOptions{}
	}
	var packets []string
	for _, packet := range []string{awg.I1, awg.I2, awg.I3, awg.I4, awg.I5} {
		if packet != "" {
			packets = append(packets, packet)
		}
	}
	return hiddify.NoiseOptions{FakePacket: hiddify.FakePacketOptions{
		Enabled: len(packets) > 0 || awg.Jc > 0,
		Packets: packets,
		Mode:    hiddify.NoiseModeRaw,
		Count:   hiddify.Range{From: int32(awg.Jc), To: int32(awg.Jc)},
		Size:    hiddify.Range{From: int32(awg.Jmin), To: int32(awg.Jmax)},
	}}
}

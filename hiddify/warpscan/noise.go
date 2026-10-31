package warpscan

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/wireguard-go/hiddify"
)

// NoisePreset is a named noise of hiddify.NoisePresets, with what the WARP endpoint and its
// scanner need of it.
type NoisePreset struct {
	Name  string
	Noise hiddify.FakePacketOptions
}

// NoisePresets are hiddify.NoisePresets, tried in this order.
var NoisePresets = func() []NoisePreset {
	presets := make([]NoisePreset, 0, len(hiddify.NoisePresets))
	for _, preset := range hiddify.NoisePresets {
		presets = append(presets, NoisePreset{Name: preset.Name, Noise: preset.Noise})
	}
	return presets
}()

// NoisePresetByName returns the preset called name, or by a short name such as dns.
func NoisePresetByName(name string) (NoisePreset, bool) {
	preset, ok := hiddify.NoisePresetByName(name)
	return NoisePreset{Name: preset.Name, Noise: preset.Noise}, ok
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

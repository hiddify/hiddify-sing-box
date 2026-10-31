package awg

import (
	"regexp"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/wireguard-go/hiddify"
)

// masqueradeDomain is a plain DNS name: the domain is written inside an i-packet tag, so nothing
// that could end the tag or start another may pass.
var masqueradeDomain = regexp.MustCompile(`^(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

// applyMasquerade turns the ip/id/ib masquerade settings into special and junk packets: ip quic
// is a fresh QUIC Initial for the domain id in i1 before every handshake; any other ip names a
// noise preset (hiddify.NoisePresets: dns, sip, stun, random, quic-mimic, ...), whose packets fill
// i1–i5 and whose junk fills jc/jmin/jmax when they are not set.
func applyMasquerade(awg *option.AwgOptions) error {
	if awg.IP == "" {
		if awg.ID != "" || awg.IB != "" {
			return E.New("awg: id and ib need ip")
		}
		return nil
	}
	if awg.I1 != "" {
		return E.New("awg: ip/id/ib replace i1, set only one of them")
	}
	if strings.ToLower(awg.IP) != "quic" {
		preset, ok := hiddify.NoisePresetByName(awg.IP)
		if !ok {
			return E.New("awg: unknown masquerade protocol: ", awg.IP)
		}
		special := []*string{&awg.I1, &awg.I2, &awg.I3, &awg.I4, &awg.I5}
		for i, packet := range preset.Noise.Packets {
			if i < len(special) {
				*special[i] = packet
			}
		}
		if awg.Jc == 0 && awg.Jmin == 0 && awg.Jmax == 0 {
			awg.Jc, awg.Jmin, awg.Jmax = int(preset.Noise.Count.To), int(preset.Noise.Size.From), int(preset.Noise.Size.To)
		}
		return nil
	}
	switch strings.ToLower(awg.IB) {
	case "", "chrome", "firefox", "curl":
	default:
		return E.New("awg: unknown masquerade client profile: ", awg.IB)
	}
	if len(awg.ID) > 253 || !masqueradeDomain.MatchString(awg.ID) {
		return E.New("awg: quic masquerade needs id, a domain name: ", awg.ID)
	}
	awg.I1 = "<qi " + strings.ToLower(awg.ID) + ">"
	return nil
}

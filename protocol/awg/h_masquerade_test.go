package awg

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// ip names a noise preset: its packets become i1–i5 and its junk jc/jmin/jmax.
func TestH_MasqueradeNamesAPreset(t *testing.T) {
	awg := option.AwgOptions{IP: "sip"}
	if err := applyMasquerade(&awg); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(awg.I1, "<b 0x494e56495445") || awg.I2 == "" || awg.I3 != "" {
		t.Fatalf("sip packets not in i1/i2: %.30s / %.30s / %q", awg.I1, awg.I2, awg.I3)
	}
	if awg.Jc == 0 || awg.Jmax == 0 {
		t.Fatalf("sip junk not applied: jc %d jmax %d", awg.Jc, awg.Jmax)
	}
	for _, name := range []string{"dns", "stun", "random", "quic-mimic", "DNS-Cloudflare"} {
		awg := option.AwgOptions{IP: name}
		if err := applyMasquerade(&awg); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// Junk set next to a preset wins over the preset's.
func TestH_MasqueradePresetKeepsJunk(t *testing.T) {
	awg := option.AwgOptions{IP: "dns", Jc: 3, Jmin: 40, Jmax: 50}
	if err := applyMasquerade(&awg); err != nil {
		t.Fatal(err)
	}
	if awg.Jc != 3 || awg.Jmin != 40 || awg.Jmax != 50 || awg.I1 == "" {
		t.Fatalf("got jc %d jmin %d jmax %d i1 %q", awg.Jc, awg.Jmin, awg.Jmax, awg.I1)
	}
}

// quic keeps needing a domain, and i1 still cannot be set next to ip.
func TestH_MasqueradeQUICAndErrors(t *testing.T) {
	awg := option.AwgOptions{IP: "quic", ID: "www.gstatic.com"}
	if err := applyMasquerade(&awg); err != nil || awg.I1 != "<qi www.gstatic.com>" {
		t.Fatalf("quic: %v, i1 %q", err, awg.I1)
	}
	for _, bad := range []option.AwgOptions{{IP: "quic"}, {IP: "sip", I1: "<b 0x00>"}, {IP: "telnet"}, {ID: "x.com"}} {
		if err := applyMasquerade(&bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

//go:build with_utls

package tls

import (
	"strings"

	utls "github.com/metacubex/utls"
)

// hChromeFingerprint is the ClientHello of the "chrome" fingerprint: Chrome 155, as Xray from
// v26.11.9, whose uTLS made it HelloChrome_Auto because TSPU does not target it yet
// (XTLS/Xray-core#7259). The uTLS fork used here still has Chrome 133 as HelloChrome_Auto; its
// Chrome 155 ClientHello is the same as upstream uTLS's.
var hChromeFingerprint = utls.HelloChrome_155

// xrayFingerprints are Xray's fingerprint names for a fixed uTLS ClientHello (its
// ModernFingerprints and OtherFingerprints), so an Xray link's fp= value works here too. The
// short names (chrome, firefox, ...) are sing-box's own and are read before these. //H
var xrayFingerprints = map[string]utls.ClientHelloID{
	"hellofirefox_120":                 utls.HelloFirefox_120,
	"hellofirefox_148":                 utls.HelloFirefox_148,
	"hellochrome_120":                  utls.HelloChrome_120,
	"hellochrome_131":                  utls.HelloChrome_131,
	"hellochrome_133":                  utls.HelloChrome_133,
	"hellochrome_155":                  utls.HelloChrome_155,
	"helloios_13":                      utls.HelloIOS_13,
	"helloios_14":                      utls.HelloIOS_14,
	"helloedge_106":                    utls.HelloEdge_106,
	"hellosafari_26_3":                 utls.HelloSafari_26_3,
	"hello360_11_0":                    utls.Hello360_11_0,
	"helloqq_11_1":                     utls.HelloQQ_11_1,
	"hellogolang":                      utls.HelloGolang,
	"hellorandomized":                  utls.HelloRandomized,
	"hellorandomizedalpn":              utls.HelloRandomizedALPN,
	"hellorandomizednoalpn":            utls.HelloRandomizedNoALPN,
	"hellofirefox_auto":                utls.HelloFirefox_Auto,
	"hellofirefox_55":                  utls.HelloFirefox_55,
	"hellofirefox_56":                  utls.HelloFirefox_56,
	"hellofirefox_63":                  utls.HelloFirefox_63,
	"hellofirefox_65":                  utls.HelloFirefox_65,
	"hellofirefox_99":                  utls.HelloFirefox_99,
	"hellofirefox_102":                 utls.HelloFirefox_102,
	"hellofirefox_105":                 utls.HelloFirefox_105,
	"hellochrome_auto":                 hChromeFingerprint,
	"hellochrome_58":                   utls.HelloChrome_58,
	"hellochrome_62":                   utls.HelloChrome_62,
	"hellochrome_70":                   utls.HelloChrome_70,
	"hellochrome_72":                   utls.HelloChrome_72,
	"hellochrome_83":                   utls.HelloChrome_83,
	"hellochrome_87":                   utls.HelloChrome_87,
	"hellochrome_96":                   utls.HelloChrome_96,
	"hellochrome_100":                  utls.HelloChrome_100,
	"hellochrome_102":                  utls.HelloChrome_102,
	"hellochrome_106_shuffle":          utls.HelloChrome_106_Shuffle,
	"helloios_auto":                    utls.HelloIOS_Auto,
	"helloios_11_1":                    utls.HelloIOS_11_1,
	"helloios_12_1":                    utls.HelloIOS_12_1,
	"helloandroid_11_okhttp":           utls.HelloAndroid_11_OkHttp,
	"helloedge_85":                     utls.HelloEdge_85,
	"helloedge_auto":                   utls.HelloEdge_Auto,
	"hellosafari_16_0":                 utls.HelloSafari_16_0,
	"hellosafari_auto":                 utls.HelloSafari_Auto,
	"hello360_auto":                    utls.Hello360_Auto,
	"hello360_7_5":                     utls.Hello360_7_5,
	"helloqq_auto":                     utls.HelloQQ_Auto,
	"hellochrome_100_psk":              utls.HelloChrome_100_PSK,
	"hellochrome_112_psk_shuf":         utls.HelloChrome_112_PSK_Shuf,
	"hellochrome_114_padding_psk_shuf": utls.HelloChrome_114_Padding_PSK_Shuf,
	"hellochrome_115_pq":               utls.HelloChrome_115_PQ,
	"hellochrome_115_pq_psk":           utls.HelloChrome_115_PQ_PSK,
	"hellochrome_120_pq":               utls.HelloChrome_120_PQ,
}

// xrayFingerprint is the ClientHello of an Xray fingerprint name, in any case. //H
func xrayFingerprint(name string) (utls.ClientHelloID, bool) {
	id, ok := xrayFingerprints[strings.ToLower(name)]
	return id, ok
}

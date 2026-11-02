// The types in this file are ported from Xray-core v26.10.31 infra/conf (common.go,
// transport_security.go, transport_method.go; https://github.com/XTLS/Xray-core, Mozilla Public
// License 2.0). Changes: TLS keeps only the client settings that realm and xdns use, without
// certificates, ECH server keys or ECH socket settings.

package finalmask

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"
)

// StringList is a JSON list of strings, or one string of comma separated items.
type StringList []string

func (v *StringList) UnmarshalJSON(data []byte) error {
	var list []string
	if err := json.Unmarshal(data, &list); err == nil {
		*v = list
		return nil
	}
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*v = strings.Split(str, ",")
		return nil
	}
	return errors.New("unknown format of a string list: " + string(data))
}

// xrayTLSConfig is the client part of Xray's tlsSettings: the TLS of a realm server and of an
// xdns DoH resolver.
type xrayTLSConfig struct {
	AllowInsecure           bool        `json:"allowInsecure"`
	ServerName              string      `json:"serverName"`
	ALPN                    *StringList `json:"alpn"`
	EnableSessionResumption bool        `json:"enableSessionResumption"`
	DisableSystemRoot       bool        `json:"disableSystemRoot"`
	MinVersion              string      `json:"minVersion"`
	MaxVersion              string      `json:"maxVersion"`
	CipherSuites            string      `json:"cipherSuites"`
	Fingerprint             string      `json:"fingerprint"`
	CurvePreferences        *StringList `json:"curvePreferences"`
	PinnedPeerCertSha256    string      `json:"pinnedPeerCertSha256"`
	VerifyPeerCertByName    string      `json:"verifyPeerCertByName"`
	ECHConfigList           string      `json:"echConfigList"`
	UseSystemCA             bool        `json:"useSystemCA"`
}

func (c *xrayTLSConfig) Build() (proto.Message, error) {
	config := new(tls.Config)
	config.ServerName = c.ServerName
	if c.ALPN != nil && len(*c.ALPN) > 0 {
		config.NextProtocol = []string(*c.ALPN)
	}
	if c.CurvePreferences != nil && len(*c.CurvePreferences) > 0 {
		config.CurvePreferences = []string(*c.CurvePreferences)
	}
	config.EnableSessionResumption = c.EnableSessionResumption
	config.DisableSystemRoot = c.DisableSystemRoot
	config.MinVersion = c.MinVersion
	config.MaxVersion = c.MaxVersion
	config.CipherSuites = c.CipherSuites
	config.Fingerprint = strings.ToLower(c.Fingerprint)
	if config.Fingerprint != "unsafe" && tls.GetFingerprint(config.Fingerprint) == nil {
		return nil, errors.New(`unknown "fingerprint": `, config.Fingerprint)
	}
	if c.AllowInsecure {
		return nil, errors.PrintRemovedFeatureError(`"allowInsecure"`, `"pinnedPeerCertSha256"(pcs) and "verifyPeerCertByName"(vcn)`)
	}
	for v := range strings.SplitSeq(c.PinnedPeerCertSha256, ",") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		hashValue, err := hex.DecodeString(strings.ReplaceAll(v, ":", ""))
		if err != nil {
			return nil, err
		}
		if len(hashValue) != 32 {
			return nil, errors.New("incorrect pinnedPeerCertSha256 length: ", v)
		}
		config.PinnedPeerCertSha256 = append(config.PinnedPeerCertSha256, hashValue)
	}
	for v := range strings.SplitSeq(c.VerifyPeerCertByName, ",") {
		if v = strings.TrimSpace(v); v != "" {
			config.VerifyPeerCertByName = append(config.VerifyPeerCertByName, v)
		}
	}
	config.EchConfigList = c.ECHConfigList
	config.UseSystemCa = c.UseSystemCA
	return config, nil
}

const (
	byteSize = 1
	kilobyte = 1024 * byteSize
	megabyte = 1024 * kilobyte
	gigabyte = 1024 * megabyte
	terabyte = 1024 * gigabyte
)

// Bandwidth is a rate in bits per second with an optional unit, "100 mbps".
type Bandwidth string

// Bps returns the rate in bytes per second.
func (b Bandwidth) Bps() (uint64, error) {
	s := strings.TrimSpace(strings.ToLower(string(b)))
	if s == "" {
		return 0, nil
	}
	idx := len(s)
	for i, c := range s {
		if (c < '0' || c > '9') && c != '.' {
			idx = i
			break
		}
	}
	val, err := strconv.ParseFloat(s[:idx], 64)
	if err != nil {
		return 0, err
	}
	var mul uint64
	switch unit := strings.TrimSpace(s[idx:]); unit {
	case "", "b", "bps":
		mul = byteSize
	case "k", "kb", "kbps":
		mul = kilobyte
	case "m", "mb", "mbps":
		mul = megabyte
	case "g", "gb", "gbps":
		mul = gigabyte
	case "t", "tb", "tbps":
		mul = terabyte
	default:
		return 0, errors.New("unsupported unit: " + unit)
	}
	return uint64(val*float64(mul)) / 8, nil
}

// PortList is a port, or a string of comma separated ports and ranges, "443,2000-3000". Xray's
// "env:" ports are not supported.
type PortList struct {
	Range []PortRange
}

// PortRange is a range of ports, both ends included.
type PortRange struct {
	From uint32
	To   uint32
}

func (list *PortList) Build() *net.PortList {
	portList := new(net.PortList)
	for _, r := range list.Range {
		portList.Range = append(portList.Range, &net.PortRange{From: r.From, To: r.To})
	}
	return portList
}

func (list *PortList) UnmarshalJSON(data []byte) error {
	var number uint32
	if err := json.Unmarshal(data, &number); err == nil {
		if number == 0 || number > math.MaxUint16 {
			return errors.New("invalid port: ", string(data))
		}
		list.Range = append(list.Range, PortRange{From: number, To: number})
		return nil
	}
	var listStr string
	if err := json.Unmarshal(data, &listStr); err != nil {
		return errors.New("invalid port: ", string(data)).Base(err)
	}
	for _, rangeStr := range strings.Split(listStr, ",") {
		trimmed := strings.TrimSpace(rangeStr)
		if trimmed == "" {
			continue
		}
		fromStr, toStr, isRange := strings.Cut(trimmed, "-")
		if !isRange {
			toStr = fromStr
		}
		from, err := strconv.ParseUint(strings.TrimSpace(fromStr), 10, 16)
		if err != nil {
			return errors.New("invalid port range: ", trimmed).Base(err)
		}
		to, err := strconv.ParseUint(strings.TrimSpace(toStr), 10, 16)
		if err != nil {
			return errors.New("invalid port range: ", trimmed).Base(err)
		}
		if from == 0 || from > to {
			return errors.New("invalid port range: ", trimmed)
		}
		list.Range = append(list.Range, PortRange{From: uint32(from), To: uint32(to)})
	}
	return nil
}

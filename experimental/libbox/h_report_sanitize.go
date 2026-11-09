package libbox

import (
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
)

// Reports leave the device unencrypted, so what could identify the user or their servers is
// taken out when they are archived: the configuration and the open connections are left out,
// and logs and other text files are scrubbed.

// sensitiveReportFile reports whether a report file is left out of an archive.
func sensitiveReportFile(name string) bool {
	return name == "configuration.json" || strings.HasSuffix(name, ".connections.json")
}

// textReportFile reports whether a report file is text to scrub; profiles and other binary
// files are copied as they are.
func textReportFile(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".log", ".txt", ".json":
		return true
	}
	return false
}

var reportScrubbers = []struct {
	pattern     *regexp.Regexp
	replacement string
}{
	// proxy share links and DNS stamps carry server, port and credentials
	{regexp.MustCompile(`(?i)\b(?:vless|vmess|trojan|ss|ssr|socks5?|hysteria2?|hy2|tuic|wireguard|wg|awg|warp|mieru|naive|anytls|shadowtls|sdns|ssh|sudoku)://[^\s"'<>]+`), "<link>"},
	// URLs keep their scheme and host, not their path and query, which can hold tokens
	{regexp.MustCompile(`(?i)\b(https?|wss?)://([^/\s"'<>?#]+)[^\s"'<>]*`), "$1://<host>"},
	{regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`), "<uuid>"},
	{regexp.MustCompile(`(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b`), "<email>"},
	// secrets written as key=value or "key": "value"
	{regexp.MustCompile(`(?i)\b(password|passwd|token|auth[_-]?token|secret|private[_-]?key|preshared[_-]?key|psk|key|cookie|license|uuid)(["']?\s*[:=]\s*["']?)[^\s"',;&]+`), "$1$2<redacted>"},
	{regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`), "<ipv4>"},
	// MAC addresses, as the BSSID of a Wi-Fi network, before IPv6, whose candidates they look like
	{regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b`), "<mac>"},
}

// ipv6Candidate is text that may be an IPv6 address; scrubIPv6 keeps only real ones, so a time
// (10:01:22) stays: every line of a log has one, and the reports were unreadable.
var ipv6Candidate = regexp.MustCompile(`(?i)[0-9a-f:]*:[0-9a-f:]*:[0-9a-f:]*(?:%[0-9a-z._-]+)?`)

func scrubIPv6(text string) string {
	var builder strings.Builder
	last := 0
	for _, match := range ipv6Candidate.FindAllStringIndex(text, -1) {
		start, end := match[0], match[1]
		// part of a word, as "d::" of "std::vector"
		if start > 0 && isWordByte(text[start-1]) || end < len(text) && isWordByte(text[end]) {
			continue
		}
		candidate := text[start:end]
		// a colon before or after the address belongs to the text around it ("from fe80::1:")
		for _, trimmed := range []string{candidate, trimSingleColons(candidate)} {
			if address, err := netip.ParseAddr(trimmed); err == nil && address.Is6() {
				builder.WriteString(text[last:start])
				builder.WriteString(strings.Replace(candidate, trimmed, "<ipv6>", 1))
				last = end
				break
			}
		}
	}
	builder.WriteString(text[last:])
	return builder.String()
}

func isWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// trimSingleColons takes a colon off each end, unless it is half of "::".
func trimSingleColons(s string) string {
	if strings.HasPrefix(s, ":") && !strings.HasPrefix(s, "::") {
		s = s[1:]
	}
	if strings.HasSuffix(s, ":") && !strings.HasSuffix(s, "::") {
		s = s[:len(s)-1]
	}
	return s
}

// sanitizeReportText removes addresses, links, user IDs and secrets from report text.
func sanitizeReportText(content []byte) []byte {
	text := string(content)
	for _, scrubber := range reportScrubbers {
		text = scrubber.pattern.ReplaceAllString(text, scrubber.replacement)
	}
	return []byte(scrubIPv6(text))
}

package libbox

import (
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
	{regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b|\[(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\]`), "<ipv6>"},
}

// sanitizeReportText removes addresses, links, user IDs and secrets from report text.
func sanitizeReportText(content []byte) []byte {
	text := string(content)
	for _, scrubber := range reportScrubbers {
		text = scrubber.pattern.ReplaceAllString(text, scrubber.replacement)
	}
	return []byte(text)
}

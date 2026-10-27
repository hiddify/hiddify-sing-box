package common

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	headless "github.com/kulikov0/headless-client"
)

const UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"

const bodySnippetLimit = 300

func BodySnippet(body []byte) string {
	if len(body) > bodySnippetLimit {
		return string(body[:bodySnippetLimit]) + "..."
	}
	return string(body)
}

func LoadCookies(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("cannot read cookies: %w", err)
	}
	var cookies []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(data, &cookies); err != nil {
		return "", fmt.Errorf("cannot parse cookies: %w", err)
	}
	parts := make([]string, len(cookies))
	for i, c := range cookies {
		parts[i] = c.Name + "=" + c.Value
	}
	return strings.Join(parts, "; "), nil
}

func UpdateCookieFile(path string, updates map[string]string) error {
	if len(updates) == 0 {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var raw []map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	seen := make(map[string]bool, len(updates))
	for _, c := range raw {
		name, _ := c["name"].(string)
		if v, ok := updates[name]; ok {
			c["value"] = v
			seen[name] = true
		}
	}
	for name, v := range updates {
		if !seen[name] {
			raw = append(raw, map[string]any{"name": name, "value": v})
		}
	}
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o600)
}

func HttpClient(dialer N.Dialer) *http.Client {
	return &http.Client{
		Transport: headless.ChromeWindows.Transport(headless.TLSOptions{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
		}),
	}
}

func HttpGet(dialer N.Dialer, endpoint string) ([]byte, error) {
	req, _ := http.NewRequest("GET", endpoint, nil)
	req.Header.Set("User-Agent", UserAgent)
	resp, err := HttpClient(dialer).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func CookieValue(cookieHeader, name string) string {
	for part := range strings.SplitSeq(cookieHeader, ";") {
		part = strings.TrimSpace(part)
		eq := strings.IndexByte(part, '=')
		if eq != -1 && part[:eq] == name {
			return part[eq+1:]
		}
	}
	return ""
}

func FilterCookies(cookieHeader string, allow []string) string {
	allowed := make(map[string]struct{}, len(allow))
	for _, n := range allow {
		allowed[n] = struct{}{}
	}
	var out []string
	for part := range strings.SplitSeq(cookieHeader, ";") {
		trimmed := strings.TrimSpace(part)
		before, _, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		if _, ok := allowed[before]; ok {
			out = append(out, trimmed)
		}
	}
	return strings.Join(out, "; ")
}

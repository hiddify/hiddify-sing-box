package common

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

func FixICEURL(iceURL string) string {
	before, after, ok := strings.Cut(iceURL, ":")
	if !ok {
		return iceURL
	}
	scheme := before
	if scheme != "turn" && scheme != "stun" && scheme != "turns" && scheme != "stuns" {
		return iceURL
	}
	rest := after
	if strings.HasPrefix(rest, "[") {
		return iceURL
	}
	if strings.Count(rest, ":") <= 1 {
		return iceURL
	}
	params := ""
	if qm := strings.Index(rest, "?"); qm >= 0 {
		params = rest[qm:]
		rest = rest[:qm]
	}
	lastColon := strings.LastIndex(rest, ":")
	if lastColon > 0 {
		host := rest[:lastColon]
		port := rest[lastColon+1:]
		if net.ParseIP(host) != nil {
			return scheme + ":[" + host + "]:" + port + params
		}
	}
	if net.ParseIP(rest) != nil {
		return scheme + ":[" + rest + "]" + params
	}
	return iceURL
}

func ExtractICEHost(iceURL string) string {
	_, after, ok := strings.Cut(iceURL, ":")
	if !ok {
		return ""
	}
	rest := after
	params := strings.Index(rest, "?")
	if params >= 0 {
		rest = rest[:params]
	}
	host, _, err := net.SplitHostPort(rest)
	if err != nil {
		return rest
	}
	return host
}

func ResolveICEHosts(urls []string, dnsRouter adapter.DNSRouter, d N.Dialer, logger logger.ContextLogger, logPrefix string) []string {
	out := make([]string, len(urls))
	copy(out, urls)
	if dnsRouter == nil {
		return out
	}
	resolved := make(map[string]string)
	for i, iceURL := range out {
		fixed := FixICEURL(iceURL)
		host := ExtractICEHost(fixed)
		if host == "" || net.ParseIP(host) != nil {
			out[i] = fixed
			continue
		}
		ip, ok := resolved[host]
		if !ok {
			addrs, err := dnsRouter.Lookup(context.Background(), host, d.(dialer.ResolveDialer).QueryOptions())
			if err != nil {
				logger.Warn(fmt.Sprintf("%s: resolve ICE host %s failed: %s", logPrefix, MaskAddr(host), MaskError(err)))
				out[i] = fixed
				continue
			}
			ip = addrs[0].String()
			resolved[host] = ip
			logger.Debug(fmt.Sprintf("%s: resolved ICE host %s -> %s", logPrefix, host, ip))
		}
		out[i] = strings.Replace(fixed, host, ip, 1)
	}
	return out
}

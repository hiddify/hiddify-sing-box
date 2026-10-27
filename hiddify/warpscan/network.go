package warpscan

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// The dialer must resolve domain names: the trace URLs are named by domain.
//
// TraceURLs report the public address of the client; the first that answers is used.
var TraceURLs = []string{
	"https://www.cloudflare.com/cdn-cgi/trace",
	"https://www.speedtest.net/cdn-cgi/trace",
}

const traceTimeout = 5 * time.Second

// NetworkInfo names the network the box is on and the address families it can reach.
type NetworkInfo struct {
	Name       string
	IPv4, IPv6 bool
}

// DetectNetwork names the network by the default interface's type and the public address seen
// by TraceURLs, through dialer: its country and its /16 (IPv4) or /32 (IPv6), so that a carrier's
// address pool or an ISP's changing address stays one network. It needs no permission (the Wi-Fi
// name does). When no trace answers, the interface type alone names it.
func DetectNetwork(ctx context.Context, logger logger.ContextLogger, dialer N.Dialer) NetworkInfo {
	info := NetworkInfo{Name: "default", IPv4: true, IPv6: true}
	interfaceType := "unknown"
	if networkManager := service.FromContext[adapter.NetworkManager](ctx); networkManager != nil {
		if defaultInterface := networkManager.DefaultNetworkInterface(); defaultInterface != nil {
			interfaceType = defaultInterface.Type.String()
			info.IPv4, info.IPv6 = addressFamilies(defaultInterface.Addresses)
		}
	}
	info.Name = interfaceType
	if address, location, ok := publicAddress(ctx, logger, dialer); ok {
		info.Name = interfaceType + "/" + location + "/" + publicPrefix(address).String()
	}
	return info
}

func addressFamilies(addresses []netip.Prefix) (ipv4 bool, ipv6 bool) {
	for _, prefix := range addresses {
		address := prefix.Addr()
		if !address.IsGlobalUnicast() || address.Is6() && !address.Is4In6() && address.IsPrivate() {
			continue
		}
		if address.Unmap().Is4() {
			ipv4 = true
		} else {
			ipv6 = true
		}
	}
	if !ipv4 && !ipv6 {
		// addresses unknown on this platform: try both
		return true, true
	}
	return ipv4, ipv6
}

func publicPrefix(address netip.Addr) netip.Prefix {
	address = address.Unmap()
	bits := 32
	if address.Is4() {
		bits = 16
	}
	prefix, _ := address.Prefix(bits)
	return prefix
}

func publicAddress(ctx context.Context, logger logger.ContextLogger, dialer N.Dialer) (netip.Addr, string, bool) {
	client := &http.Client{
		Timeout: traceTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, M.ParseSocksaddr(address))
			},
		},
	}
	defer client.CloseIdleConnections()
	for _, url := range TraceURLs {
		address, location, err := trace(ctx, client, url)
		if err == nil {
			return address, location, true
		}
		logger.DebugContext(ctx, "WARP scanner: ", url, ": ", err)
	}
	return netip.Addr{}, "", false
}

func trace(ctx context.Context, client *http.Client, url string) (netip.Addr, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return netip.Addr{}, "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return netip.Addr{}, "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return netip.Addr{}, "", fmt.Errorf("trace: %s", response.Status)
	}
	return parseTrace(io.LimitReader(response.Body, 4096))
}

// parseTrace reads the ip= and loc= lines of a cdn-cgi/trace answer.
func parseTrace(reader io.Reader) (netip.Addr, string, error) {
	var (
		address  netip.Addr
		location string
	)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		key, value, _ := strings.Cut(scanner.Text(), "=")
		switch key {
		case "ip":
			address, _ = netip.ParseAddr(value)
		case "loc":
			location = value
		}
	}
	if !address.IsValid() {
		return netip.Addr{}, "", fmt.Errorf("trace: no ip")
	}
	return address, location, nil
}

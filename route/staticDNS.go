package route

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/outbound"
	dns "github.com/sagernet/sing-dns"
)

type DnsResult struct {
	Domain string
	IPs    []netip.Addr
}
type StaticDNS struct {
	entries          map[string]StaticDNSEntry
	regexEntries     map[*regexp.Regexp]StaticDNSEntry
	internalDNSItems map[string]bool
	router           *Router
	mu               sync.Mutex

	ipMaps      map[string]*DnsResult
	ipMapsMutex sync.Mutex
}

func NewStaticDNS(router *Router, staticIPs map[string][]string) *StaticDNS {
	s := &StaticDNS{
		internalDNSItems: make(map[string]bool),
		router:           router,
		ipMaps:           map[string]*DnsResult{},
		entries:          make(map[string]StaticDNSEntry),
		regexEntries:     make(map[*regexp.Regexp]StaticDNSEntry),
	}
	s.createEntries(staticIPs)
	if router == nil {
		return nil
	}
	for _, out := range router.Outbounds() {
		if urltest, ok := out.(*outbound.URLTest); ok && out.Type() == C.TypeURLTest && urltest != nil {
			for _, link := range urltest.Links() {
				domain := getDomainFromLink(link)
				if domain != "" && !IsIPv6(domain) && !IsIPv4(domain) {
					s.internalDNSItems[domain] = true
				}
			}
		}
	}

	return s
}

func getDomainFromLink(link string) string {
	url, err := url.Parse(link)
	if err != nil {
		return ""
	}
	return url.Hostname()
}

type StaticDNSEntry struct {
	IPv4 []netip.Addr
	IPv6 []netip.Addr
}

func isBlockedIP(ip string) bool {
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "2001:4188:2:600:10") {
		return true
	}
	return false
}

func (s *StaticDNS) resolveDomain(ctx context.Context, domain string) *DnsResult {
	s.ipMapsMutex.Lock()
	// fmt.Println("pre resolve", domain, ipMaps)
	if res, ok := s.ipMaps[domain]; ok {
		s.ipMapsMutex.Unlock()
		// fmt.Println("aleady", domain, res)
		return res
	}
	s.ipMapsMutex.Unlock()
	ips := make([]net.IP, 0)

	if ip := net.ParseIP(domain); ip != nil {
		ips = append(ips, ip)
	} else {
		var err error
		ips, err = net.DefaultResolver.LookupIP(ctx, "ip", domain)

		if err != nil {
			fmt.Println("error", err, domain, ips)
			return nil
		}
	}
	// fmt.Println("hresolve", domain, ips)
	res := &DnsResult{Domain: domain, IPs: make([]netip.Addr, 0)}
	for _, ip := range ips {
		ipStr := ip.String()
		if !isBlockedIP(ipStr) {
			ipnet, err := netip.ParseAddr(ipStr)
			if err != nil {
				continue
			}
			res.IPs = append(res.IPs, ipnet)
		}
	}
	if len(res.IPs) != 0 {
		s.ipMapsMutex.Lock()
		s.ipMaps[domain] = res
		s.ipMapsMutex.Unlock()

	}
	return res

}
func (s *StaticDNS) getIPs(tag string, domains ...string) []netip.Addr {

	var wg sync.WaitGroup
	resChan := make(chan *DnsResult, len(domains)*10) // Collect both IPv4 and IPv6
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	for _, d := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			resChan <- s.resolveDomain(ctx, d)
		}(d)
	}

	go func() {
		wg.Wait()
		close(resChan)
	}()

	var res []netip.Addr = make([]netip.Addr, 0)
	for dnsres := range resChan {
		if dnsres != nil {
			res = append(res, dnsres.IPs...)
		}
	}

	return res
}

func (s *StaticDNS) createEntries(items map[string][]string) {

	var wg sync.WaitGroup

	for domain, domainList := range items {
		wg.Add(1)
		go func(d string, dList []string) {
			defer wg.Done()
			ips := s.getIPs(d, dList...)
			fmt.Println("d", d, "list", dList, "ips", ips)
			if len(ips) > 0 {
				s.add2staticDns(d, ips)
			}
		}(domain, domainList)
	}
	wg.Wait()

}

func errorIfEmpty(addrs []netip.Addr) ([]netip.Addr, error) {
	if len(addrs) == 0 {
		return addrs, fmt.Errorf("NotFound")
	}
	return addrs, nil
}

func (s *StaticDNS) Add2staticDnsIfInternal(domain string, addrs []netip.Addr) {
	if s == nil || s.internalDNSItems == nil {
		// fmt.Println("StaticDNS or internalDNSItems is nil")
		return
	}

	if _, ok := s.internalDNSItems[domain]; !ok {
		return
	}

	if len(addrs) == 0 {
		// fmt.Println("No addresses provided for domain:", domain)
		return
	}

	s.add2staticDns(domain, addrs)
}

func (s *StaticDNS) add2staticDns(domain string, addrs []netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := StaticDNSEntry{}
	for _, ip := range addrs {
		if isBlocked(ip) {
			continue
		}
		if ip.Is4() {
			entry.IPv4 = append(entry.IPv4, ip)
		} else {
			entry.IPv6 = append(entry.IPv6, ip)
		}
	}
	if len(entry.IPv4) == 0 && len(entry.IPv6) == 0 {
		return
	}
	if strings.HasPrefix(domain, "re:") {
		regexPattern := strings.TrimPrefix(domain, "re:")
		re, err := regexp.Compile(regexPattern)
		if err != nil {
			fmt.Printf("Invalid regex: %s\n", regexPattern)
			return
		}

		s.regexEntries[re] = entry
	} else {
		s.entries[domain] = entry
	}

}

func (s *StaticDNS) IsInternal(domain string) bool {
	if _, ok := s.internalDNSItems[domain]; ok {
		return true
	}
	return false
}
func (s *StaticDNS) regexMatch(domain string) (StaticDNSEntry, error) {
	if staticDns, ok := s.entries[domain]; ok {
		return staticDns, nil
	}

	for re, entry := range s.regexEntries {
		fmt.Println("Matching ", domain, "with ", re, "res=", re.MatchString(domain))
		if re.MatchString(domain) {
			return entry, nil
		}
	}
	return StaticDNSEntry{}, fmt.Errorf("NotFound")
}
func (s *StaticDNS) lookupStaticIP(domain string, strategy uint8, skipInternal bool) ([]netip.Addr, error) {
	if skipInternal && s.IsInternal(domain) {
		return nil, fmt.Errorf("Internal")
	}

	if staticDns, err := s.regexMatch(domain); err == nil {
		switch strategy {
		case dns.DomainStrategyUseIPv4:
			return errorIfEmpty(staticDns.IPv4)

		case dns.DomainStrategyUseIPv6:

			return errorIfEmpty(staticDns.IPv6)

		case dns.DomainStrategyPreferIPv6:
			if len(staticDns.IPv6) == 0 {
				return errorIfEmpty(staticDns.IPv4)
			}
			return errorIfEmpty(append(staticDns.IPv6, staticDns.IPv4...))

		default:
			if len(staticDns.IPv4) == 0 {
				return errorIfEmpty(staticDns.IPv6)
			}
			return errorIfEmpty(append(staticDns.IPv4, staticDns.IPv6...))

		}

	} else {
		ip := getIpOfSslip(domain)
		if ip != "" {
			ipaddr, err := netip.ParseAddr(ip)
			if err != nil {
				return nil, err
			}
			return []netip.Addr{ipaddr}, nil
		}
		// if strings.Contains(domain, ",") {
		// 	entry := StaticDNSEntry{}
		// 	for _, ipString := range strings.Split(domain, ",") {
		// 		ip, err := netip.ParseAddr(ipString)
		// 		if err != nil {
		// 			fmt.Printf("Invalid IP address for domain %s: %s\n", domain, ipString)
		// 			continue
		// 		}

		// 		if ip.Is4() {
		// 			entry.IPv4 = append(entry.IPv4, ip)
		// 		} else {
		// 			entry.IPv6 = append(entry.IPv6, ip)
		// 		}
		// 	}
		// 	fmt.Println("Adding ",domain, entry)
		// 	router.staticDns[domain] = entry
		// 	return router.lookupStaticIP(domain, strategy)
		// }
		return nil, fmt.Errorf("NotFound")
	}
}

const (
	ipv4Pattern = `((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])[\.-](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])[\.-](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])[\.-](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])).sslip.io$`
	ipv6Pattern = `((([0-9a-fA-F]{1,4}-){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}-){1,7}-|([0-9a-fA-F]{1,4}-){1,6}-[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}-){1,5}(-[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}-){1,4}(-[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}-){1,3}(-[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}-){1,2}(-[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}-((-[0-9a-fA-F]{1,4}){1,6})|-((-[0-9a-fA-F]{1,4}){1,7}|-)|fe80-(-[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|--(ffff(-0{1,4}){0,1}-){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}-){1,4}-((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))).sslip.io$`
)

var (
	ipv4Regex, _ = regexp.Compile(ipv4Pattern)
	ipv6Regex, _ = regexp.Compile(ipv6Pattern)
)

func IsIPv4(sni string) bool {
	return ipv4Regex.MatchString(sni)
}

func IsIPv6(sni string) bool {
	return ipv6Regex.MatchString(sni)
}

func getIpOfSslip(sni string) string {
	if !strings.HasSuffix(sni, ".sslip.io") {
		return ""
	}
	submatches := ipv4Regex.FindStringSubmatch(sni)
	if len(submatches) > 1 {
		return strings.ReplaceAll(submatches[1], "-", ".")
	} else {
		submatches := ipv6Regex.FindStringSubmatch(sni)
		if len(submatches) > 1 {
			return strings.ReplaceAll(submatches[1], "-", ":")
		}
	}
	return ""
}

package hosts

import (
	"context"
	"net/netip"
	"os"
	"regexp"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service/filemanager"

	mDNS "github.com/miekg/dns"
)

func RegisterTransport(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.HostsDNSServerOptions](registry, C.DNSTypeHosts, NewTransport)
}

var (
	_ adapter.DNSTransport                    = (*Transport)(nil)
	_ adapter.DNSTransportWithPreferredDomain = (*Transport)(nil)
)

type Transport struct {
	dns.TransportAdapter
	files      []*File
	predefined map[string][]netip.Addr
}

func NewTransport(ctx context.Context, logger log.ContextLogger, tag string, options option.HostsDNSServerOptions) (adapter.DNSTransport, error) {
	var (
		files      []*File
		predefined = make(map[string][]netip.Addr)
	)
	if len(options.Path) == 0 {
		defaultFile, err := NewDefault()
		if err != nil {
			return nil, err
		}
		files = append(files, defaultFile)
	} else {
		for _, path := range options.Path {
			files = append(files, NewFile(filemanager.BasePath(ctx, os.ExpandEnv(path))))
		}
	}
	if options.Predefined != nil {
		for _, entry := range options.Predefined.Entries() {
			predefined[mDNS.CanonicalName(entry.Key)] = entry.Value
		}
	}
	return &Transport{
		TransportAdapter: dns.NewTransportAdapter(C.DNSTypeHosts, tag, nil),
		files:            files,
		predefined:       predefined,
	}, nil
}

func (t *Transport) Start(stage adapter.StartStage) error {
	return nil
}

func (t *Transport) Close() error {
	return nil
}

func (t *Transport) Reset() {
}

func (t *Transport) PreferredDomain(domain string) bool {
	if _, loaded := t.predefined[domain]; loaded {
		return true
	}
	for _, file := range t.files {
		if len(file.Lookup(domain)) > 0 {
			return true
		}
	}
	return false
}

func (t *Transport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	question := message.Question[0]
	domain := mDNS.CanonicalName(question.Name)
	if question.Qtype == mDNS.TypeA || question.Qtype == mDNS.TypeAAAA {
		if addresses, ok := t.predefined[domain]; ok {
			return dns.FixedResponse(message.Id, question, addresses, C.DefaultDNSTTL), nil
		}
		for _, file := range t.files {
			addresses := file.Lookup(domain)
			if len(addresses) > 0 {
				return dns.FixedResponse(message.Id, question, addresses, C.DefaultDNSTTL), nil
			}
		}
		addresses := getIpOfSslip(domain)
		if len(addresses) > 0 {
			return dns.FixedResponse(message.Id, question, addresses, C.DefaultDNSTTL), nil
		}
	}
	return &mDNS.Msg{
		MsgHdr: mDNS.MsgHdr{
			Id:       message.Id,
			Rcode:    mDNS.RcodeNameError,
			Response: true,
		},
		Question: []mDNS.Question{question},
	}, nil
}

const (
	ipv4Pattern = `((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])[\.-](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])[\.-](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])[\.-](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])).sslip.io$`
	ipv6Pattern = `((([0-9a-fA-F]{1,4}-){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}-){1,7}-|([0-9a-fA-F]{1,4}-){1,6}-[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}-){1,5}(-[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}-){1,4}(-[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}-){1,3}(-[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}-){1,2}(-[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}-((-[0-9a-fA-F]{1,4}){1,6})|-((-[0-9a-fA-F]{1,4}){1,7}|-)|fe80-(-[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|--(ffff(-0{1,4}){0,1}-){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}-){1,4}-((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))).sslip.io$`
)

var (
	ipv4Regex, _ = regexp.Compile(ipv4Pattern)
	ipv6Regex, _ = regexp.Compile(ipv6Pattern)
)

func getIpOfSslip(sni string) []netip.Addr {
	if !strings.HasSuffix(sni, ".sslip.io") {
		return nil
	}
	submatches := ipv4Regex.FindStringSubmatch(sni)
	ipstr := ""
	if len(submatches) > 1 {
		ipstr = strings.ReplaceAll(submatches[1], "-", ".")

	} else {
		submatches := ipv6Regex.FindStringSubmatch(sni)
		if len(submatches) > 1 {
			ipstr = strings.ReplaceAll(submatches[1], "-", ":")
		}
	}
	ip, err := netip.ParseAddr(ipstr)
	if err != nil {
		return nil
	}
	return []netip.Addr{ip}

}

package dnspool

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"time"

	multidns "github.com/hiddify/hmrd_multi_resolver_dns"
	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// ProbeTimeout is how long one probe may take.
const ProbeTimeout = 5 * time.Second

// QueryType reads a record type name (a, aaaa, cname, mx, ns, ptr, soa, srv, txt); anything else
// is A.
func QueryType(record string) uint16 {
	switch record {
	case "a":
		return mDNS.TypeA
	case "aaaa":
		return mDNS.TypeAAAA
	case "cname":
		return mDNS.TypeCNAME
	case "mx":
		return mDNS.TypeMX
	case "ns":
		return mDNS.TypeNS
	case "ptr":
		return mDNS.TypePTR
	case "soa":
		return mDNS.TypeSOA
	case "srv":
		return mDNS.TypeSRV
	case "txt":
		return mDNS.TypeTXT
	default:
		return mDNS.TypeA
	}
}

// BuildQuery builds a recursive query for name and qtype.
func BuildQuery(name string, qtype uint16) *mDNS.Msg {
	m := new(mDNS.Msg)
	m.SetQuestion(mDNS.Fqdn(name), qtype)
	m.RecursionDesired = true
	return m
}

// Probe sends one ordinary query for name to a resolver and returns the answer. It is the check
// a tunnel runs before it uses a resolver: a resolver that does not answer a normal query will
// not carry a tunnel either. The resolver is written as the pool reads it ("1.1.1.1:53",
// "tcp://...", "dot://host:853", "https://host/dns-query"); the query uses sing-box's DNS
// transports with the given dialer options, so bind_interface and the platform's socket
// protection apply.
func Probe(ctx context.Context, logger log.ContextLogger, resolver string, name string, qtype uint16, dialerOptions option.DialerOptions) (*mDNS.Msg, error) {
	config, err := multidns.ParseResolverURL(resolver)
	if err != nil {
		return nil, err
	}
	local := option.RawLocalDNSServerOptions{DialerOptions: dialerOptions}
	var trans adapter.DNSTransport
	switch config.Protocol {
	case multidns.ProtoDoH:
		u, err := url.Parse(config.Address)
		if err != nil {
			return nil, err
		}
		port := uint16(443)
		if p := u.Port(); p != "" {
			n, err := strconv.ParseUint(p, 10, 16)
			if err != nil {
				return nil, E.Cause(err, "resolver port")
			}
			port = uint16(n)
		}
		trans, err = transport.NewHTTPS(ctx, logger, "probe", option.RemoteHTTPSDNSServerOptions{
			RemoteTLSDNSServerOptions: option.RemoteTLSDNSServerOptions{
				RemoteDNSServerOptions: option.RemoteDNSServerOptions{
					RawLocalDNSServerOptions: local,
					DNSServerAddressOptions:  option.DNSServerAddressOptions{Server: u.Hostname(), ServerPort: port},
				},
			},
			Path: u.Path,
		})
		if err != nil {
			return nil, err
		}
	default:
		host, portStr, err := net.SplitHostPort(config.Address)
		if err != nil {
			return nil, err
		}
		n, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return nil, E.Cause(err, "resolver port")
		}
		remote := option.RemoteDNSServerOptions{
			RawLocalDNSServerOptions: local,
			DNSServerAddressOptions:  option.DNSServerAddressOptions{Server: host, ServerPort: uint16(n)},
		}
		switch config.Protocol {
		case multidns.ProtoTCP:
			trans, err = transport.NewTCP(ctx, logger, "probe", remote)
		case multidns.ProtoDoT:
			trans, err = transport.NewTLS(ctx, logger, "probe", option.RemoteTLSDNSServerOptions{RemoteDNSServerOptions: remote})
		default:
			trans, err = transport.NewUDP(ctx, logger, "probe", remote)
		}
		if err != nil {
			return nil, err
		}
	}

	scope := adapter.NewScope(ctx, logger) // the transport lives only for this query
	defer scope.Close()
	if err := scope.Start("dns/probe", trans, adapter.StartStateStart); err != nil {
		return nil, err
	}
	queryCtx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()
	return trans.Exchange(queryCtx, BuildQuery(name, qtype))
}

// CheckAnswer is the probe's verdict: an error when the answer is missing or empty.
func CheckAnswer(resolver string, response *mDNS.Msg, err error) error {
	if err != nil {
		return err
	}
	if response == nil || len(response.Answer) == 0 {
		return E.New("no record in the answer of resolver ", resolver)
	}
	return nil
}

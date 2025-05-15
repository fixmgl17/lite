package dns

import (
	"context"
	"fmt"
	"lite/common"
	"net"
	"time"

	"github.com/miekg/dns"
)

var (
	_ Resolver = (*standardResolver)(nil)
)

type dnsExchanger interface {
	ExchangeContext(ctx context.Context, m *dns.Msg) (msg *dns.Msg, rtt time.Duration, err error)
}

type standardResolver struct {
	Exchanger dnsExchanger
}

// skipCNAMEChain skips the CNAME chain and returns the last CNAME target.
// Sometimes the DNS server returns a CNAME chain like this, in one packet:
// domain1.com. CNAME domain2.com.
// domain2.com. CNAME domain3.com.
// In this case, we should avoid sending a query for domain2.com and go
// straight to domain3.com.
func (r *standardResolver) skipCNAMEChain(answers []dns.RR) string {
	var lastCNAME string
	for _, a := range answers {
		if cname, ok := a.(*dns.CNAME); ok {
			if lastCNAME == "" {
				// First CNAME
				lastCNAME = cname.Target
			} else if cname.Hdr.Name == lastCNAME {
				// CNAME chain
				lastCNAME = cname.Target
			} else {
				// CNAME chain ends
				return lastCNAME
			}
		}
	}
	return lastCNAME
}

func (r *standardResolver) LookupIPv4(ctx context.Context, host string) ([]net.IP, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	resp, _, err := r.Exchanger.ExchangeContext(ctx, m)
	if err != nil {
		return nil, err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
	case dns.RcodeNameError:
		return nil, ErrNXDomain
	default:
		return nil, fmt.Errorf("reply code %d: %s", resp.Rcode, dns.RcodeToString[resp.Rcode])
	}
	// Sometimes the DNS server returns both CNAME and A records in one packet.
	var hasCNAME bool
	var ipv4List []net.IP
	for _, a := range resp.Answer {
		if aa, ok := a.(*dns.A); ok {
			ipv4List = append(ipv4List, aa.A.To4())
		} else if _, ok := a.(*dns.CNAME); ok {
			hasCNAME = true
		}
	}
	if len(ipv4List) > 0 {
		return ipv4List, nil
	}
	if hasCNAME {
		return r.LookupIPv4(ctx, r.skipCNAMEChain(resp.Answer))
	} else {
		// Should not happen
		return nil, ErrNXDomain
	}
}

func (r *standardResolver) LookupIPv6(ctx context.Context, host string) ([]net.IP, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
	resp, _, err := r.Exchanger.ExchangeContext(ctx, m)
	if err != nil {
		return nil, err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
	case dns.RcodeNameError:
		return nil, ErrNXDomain
	default:
		return nil, fmt.Errorf("reply code %d: %s", resp.Rcode, dns.RcodeToString[resp.Rcode])
	}
	// Sometimes the DNS server returns both CNAME and AAAA records in one packet.
	var hasCNAME bool
	var ipv6List []net.IP
	for _, a := range resp.Answer {
		if aa, ok := a.(*dns.AAAA); ok {
			ipv6List = append(ipv6List, aa.AAAA.To16())
		} else if _, ok := a.(*dns.CNAME); ok {
			hasCNAME = true
		}
	}
	if len(ipv6List) > 0 {
		return ipv6List, nil
	}
	if hasCNAME {
		return r.LookupIPv6(ctx, r.skipCNAMEChain(resp.Answer))
	} else {
		// Should not happen
		return nil, ErrNXDomain
	}
}

func (r *standardResolver) LookupIP(ctx context.Context, host string) (ipv4 []net.IP, ipv6 []net.IP, err error) {
	return lookupIPViaResolver(ctx, r, host)
}

func (r *standardResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	reverseName, err := dns.ReverseAddr(addr)
	if err != nil {
		return nil, err
	}
	m := new(dns.Msg)
	m.SetQuestion(reverseName, dns.TypePTR)
	resp, _, err := r.Exchanger.ExchangeContext(ctx, m)
	if err != nil {
		return nil, err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
	case dns.RcodeNameError:
		return nil, ErrNXDomain
	default:
		return nil, fmt.Errorf("reply code %d: %s", resp.Rcode, dns.RcodeToString[resp.Rcode])
	}
	var domains []string
	for _, ans := range resp.Answer {
		if ptr, ok := ans.(*dns.PTR); ok {
			domains = append(domains, ptr.Ptr)
		}
	}
	// Should not happen
	if len(domains) == 0 {
		return nil, ErrNXDomain
	}
	return domains, nil
}

func (r *standardResolver) Close() error {
	return common.TryToClose(r.Exchanger)
}

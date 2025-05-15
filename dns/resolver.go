package dns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"lite/common"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/miekg/dns"
)

// Scheme: "udp", "https", "system"
func NewResolver(urlStr string) (Resolver, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "system" {
		return &systemResolver{
			Resolver: net.Resolver{
				PreferGo: true,
			},
		}, nil
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = map[string]string{"udp": "53", "https": "443"}[u.Scheme]
	}
	u.Host = net.JoinHostPort(host, port)
	r := &standardResolver{}
	switch u.Scheme {
	case "udp":
		r.Exchanger = &udpExchanger{
			Addr: u.Host,
			Client: &dns.Client{
				Net:     "udp",
				Timeout: time.Second * 2,
			},
		}
	case "https":
		if u.Path == "" {
			u.Path = "/dns-query"
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		r.Exchanger = &httpsExchanger{
			URL: u,
			HTTPClient: &http.Client{
				Transport: tr,
				Timeout:   time.Second * 3,
			},
		}
	default:
		return nil, fmt.Errorf("unsupported scheme %s", u.Scheme)
	}
	return r, nil
}

var (
	_ Resolver = (*systemResolver)(nil)
)

type systemResolver struct {
	Resolver net.Resolver
}

func (r *systemResolver) lookupIP(ctx context.Context, network string, host string) ([]net.IP, error) {
	ipList, err := r.Resolver.LookupIP(ctx, network, host)
	if err != nil {
		if err, ok := err.(*net.DNSError); ok && err.IsNotFound {
			return nil, ErrNXDomain
		}
		return nil, err
	}
	if len(ipList) == 0 {
		return nil, ErrNXDomain
	}
	return ipList, err
}

func (r *systemResolver) LookupIPv4(ctx context.Context, host string) ([]net.IP, error) {
	return r.lookupIP(ctx, "ip4", host)
}

func (r *systemResolver) LookupIPv6(ctx context.Context, host string) ([]net.IP, error) {
	return r.lookupIP(ctx, "ip6", host)
}

func (r *systemResolver) LookupIP(ctx context.Context, host string) ([]net.IP, []net.IP, error) {
	ipList, err := r.lookupIP(ctx, "ip", host)
	if err != nil {
		if err, ok := err.(*net.DNSError); ok && err.IsNotFound {
			return nil, nil, ErrNXDomain
		}
		return nil, nil, err
	}
	var ipv4List, ipv6List []net.IP
	for _, ip := range ipList {
		if ip := ip.To4(); ip != nil {
			ipv4List = append(ipv4List, ip)
		} else {
			ipv6List = append(ipv6List, ip)
		}
	}
	if len(ipv4List) == 0 && len(ipv6List) == 0 {
		return nil, nil, ErrNXDomain
	}
	return ipv4List, ipv6List, nil
}

var (
	_ dnsExchanger = (*udpExchanger)(nil)
	_ dnsExchanger = (*httpsExchanger)(nil)
)

type udpExchanger struct {
	Addr string
	*dns.Client
}

func (e *udpExchanger) ExchangeContext(ctx context.Context, m *dns.Msg) (msg *dns.Msg, rtt time.Duration, err error) {
	return e.Client.ExchangeContext(ctx, m, e.Addr)
}

type httpsExchanger struct {
	URL        *url.URL
	HTTPClient *http.Client
}

func (c *httpsExchanger) ExchangeContext(ctx context.Context, m *dns.Msg) (msg *dns.Msg, rtt time.Duration, err error) {
	b, err := m.Pack()
	if err != nil {
		return
	}
	begin := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL.String(), bytes.NewReader(b))
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", common.DefaultUserAgent)
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("HTTPS server returned with non-OK code %d", resp.StatusCode)
		return
	}
	buf := common.GetBuffer(1024)
	defer common.PutBuffer(buf)
	n, err := io.ReadFull(resp.Body, buf)
	if err != nil && err != io.ErrUnexpectedEOF {
		return
	}
	rtt = time.Since(begin)
	msg = new(dns.Msg)
	err = msg.Unpack(buf[:n])
	if err == nil && msg.Id != m.Id {
		err = dns.ErrId
	}
	return
}

func (c *httpsExchanger) Close() error {
	c.HTTPClient.CloseIdleConnections()
	return nil
}

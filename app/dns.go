package app

import (
	"context"
	"fmt"
	"lite/common"
	"lite/dns"
	"math/rand/v2"
	"net"
	"strings"
	"time"
)

func BuildDNSClient(config *DNSConfig) (*dns.Client, error) {
	ttl := time.Minute * 5
	var err error
	if config.TTL != "" {
		config.TTL = strings.ToLower(strings.Trim(config.TTL, " "))
		ttl, err = time.ParseDuration(config.TTL)
		if err != nil {
			return nil, fmt.Errorf("parse ttl: %w", err)
		}
	}
	return dns.NewClient(config.ServerURL, ttl)
}

func LookupIPWithMode(ctx context.Context, r dns.Resolver, mode dnsResolveEnum, host string) (net.IP, net.IP, error) {
	var ipv4List, ipv6List []net.IP
	var err error
	switch mode {
	case DNSResolve4:
		ipv4List, err = r.LookupIPv4(ctx, host)
	case DNSResolve6:
		ipv6List, err = r.LookupIPv6(ctx, host)
	case DNSResolveAuto:
		ipv4List, ipv6List, err = r.LookupIP(ctx, host)
	case DNSResolve46:
		ipv4List, err = r.LookupIPv4(ctx, host)
		if err != nil {
			ipv6List, err = r.LookupIPv6(ctx, host)
		}
	case DialMode64:
		ipv6List, err = r.LookupIPv6(ctx, host)
		if err != nil {
			ipv4List, err = r.LookupIPv4(ctx, host)
		}
	default:
		err = fmt.Errorf("unknown dns resolve mode %s", mode)
	}
	if err != nil {
		return nil, nil, err
	}
	var ipv4, ipv6 net.IP
	if n := len(ipv4List); n > 0 {
		ipv4 = ipv4List[rand.IntN(n)]
	}
	if n := len(ipv6List); n > 0 {
		ipv6 = ipv6List[rand.IntN(n)]
	}
	return ipv4, ipv6, nil
}

func resolveIPWithMode(ctx context.Context, r dns.Resolver, mode dnsResolveEnum, addr *common.NetAddr) error {
	if mode == "" || addr.IsIP() {
		return nil
	}
	ipv4, ipv6, err := LookupIPWithMode(ctx, r, mode, addr.FQDN)
	if err != nil {
		return err
	}
	addr.FQDN = ""
	if ipv4 != nil {
		addr.SetIPv4(ipv4)
	} else {
		addr.SetIPv6(ipv6)
	}
	return nil
}

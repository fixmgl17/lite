package app

import (
	"bytes"
	"fmt"
	"lite/common"
	"lite/geo"
	"lite/pkg"
	"math/rand/v2"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type Routing struct {
	Rules []*RoutingRule
}

type networkEnum string

const (
	NetworkAny networkEnum = ""
	NetworkTCP networkEnum = "tcp"
	NetworkUDP networkEnum = "udp"
)

type dnsResolveEnum string

const (
	// Concurrently lookup ipv4 and ipv6
	DNSResolveAuto dnsResolveEnum = "auto"
	DNSResolve46   dnsResolveEnum = "46"
	DNSResolve64   dnsResolveEnum = "64"
	DNSResolve4    dnsResolveEnum = "4"
	DNSResolve6    dnsResolveEnum = "6"
)

type RoutingRule struct {
	From           *pkg.TimeClock
	To             *pkg.TimeClock
	RequireIPv6    bool
	Network        networkEnum
	PortRange      map[uint16]struct{}
	InboundTags    map[string]struct{}
	OutboundTags   map[string]struct{}
	IncludeMatcher *HostMatcher
	ExcludeMatcher *HostMatcher
	DNSResolve     dnsResolveEnum
}

func (r *RoutingRule) HasInboundTag(tag string) bool {
	_, ok := r.InboundTags[tag]
	return ok
}

func (r *RoutingRule) HitInboundTags(tag string) bool {
	if len(r.InboundTags) == 0 {
		return true
	}
	return r.HasInboundTag(tag)
}

func (r *RoutingRule) HasOutboundTag(tag string) bool {
	_, ok := r.OutboundTags[tag]
	return ok
}

func (r *RoutingRule) HitOutboundTags(tag string) bool {
	return r.HasOutboundTag(tag)
}

func (r *RoutingRule) IsWorkingTime() bool {
	if r.From == nil || r.To == nil {
		return true
	}
	now := time.Now()
	c := &pkg.TimeClock{Hour: now.Hour(), Minute: now.Minute(), Second: now.Second()}
	return c.Compare(r.From) >= 0 && c.Compare(r.To) <= 0
}

func (r *Routing) Validate(inbounds []*Inbound, outbounds []*Outbound) error {
	for i, r := range r.Rules {
		for tag := range r.InboundTags {
			exist := false
			for _, inb := range inbounds {
				if inb.Tag == tag {
					exist = true
					break
				}
			}
			if !exist && tag != GeoTag {
				return fmt.Errorf("the %dth routing rule: unknown inbound tag: %s", i+1, tag)
			}
		}
		for tag := range r.OutboundTags {
			exist := false
			for _, ob := range outbounds {
				if ob.Tag == tag {
					exist = true
					break
				}
			}
			if !exist {
				return fmt.Errorf("the %dth routing rule: unknown outbound tag: %s", i+1, tag)
			}
		}
	}
	return nil
}

func (r *Routing) Match(inbTag string, addr *common.NetAddr, outbounds []*Outbound) *Outbound {
	_ = outbounds[0]
	var matchedOutbounds []*Outbound
	for _, rule := range r.Rules {
		if !rule.IsWorkingTime() || !rule.HitInboundTags(inbTag) {
			continue
		}
		if rule.RequireIPv6 && !common.CheckIPv6ByDial() {
			continue
		}
		if rule.Network != NetworkAny {
			if rule.Network == NetworkTCP {
				if !addr.IsTCP() {
					continue
				}
			} else if rule.Network == NetworkUDP {
				if !addr.IsUDP() {
					continue
				}
			}
		}
		if rule.PortRange != nil {
			_, ok := rule.PortRange[addr.Port]
			if !ok {
				continue
			}
		}
		if rule.IncludeMatcher != nil && !rule.IncludeMatcher.Match(addr) {
			continue
		}
		if rule.ExcludeMatcher != nil && rule.ExcludeMatcher.Match(addr) {
			continue
		}
		for _, ob := range outbounds {
			if rule.HitOutboundTags(ob.Tag) {
				matchedOutbounds = append(matchedOutbounds, ob)
			}
		}
		if len(matchedOutbounds) > 0 {
			break
		}
	}
	if len(matchedOutbounds) == 0 {
		return outbounds[0]
	}
	return matchedOutbounds[rand.IntN(len(matchedOutbounds))]
}

func BuildRouting(config *RoutingConfig) (*Routing, error) {
	routing := &Routing{}
	h := &geoHandle{}
	defer h.Release()
	for i, rule := range config.Rules {
		r := &RoutingRule{
			OutboundTags: make(map[string]struct{}),
		}
		if rule.TimeRange != "" {
			from, to, err := pkg.ParseTimeRange(rule.TimeRange)
			if err != nil {
				return nil, fmt.Errorf("the %dth routing rule: %w", i+1, err)
			}
			if from == nil {
				from = &pkg.TimeClock{}
			}
			if to == nil {
				to = &pkg.TimeClock{Hour: 23, Minute: 59, Second: 59}
			}
			if to.Compare(from) < 0 {
				return nil, fmt.Errorf("the %dth routing rule: invalid time range: %s", i+1, rule.TimeRange)
			}
			r.From = from
			r.To = to
		}
		r.RequireIPv6 = rule.RequireIPv6
		rule.Network = networkEnum(strings.ToLower(string(rule.Network)))
		switch rule.Network {
		case NetworkAny, NetworkTCP, NetworkUDP:
			r.Network = rule.Network
		default:
			return nil, fmt.Errorf("the %dth routing rule: unknown network: %s", i+1, rule.Network)
		}
		if rule.PortRange != "" {
			ports, err := pkg.ParsePortRange(rule.PortRange)
			if err != nil {
				return nil, fmt.Errorf("the %dth routing rule: %w", i+1, err)
			}
			if len(ports) > 0 {
				r.PortRange = make(map[uint16]struct{})
				for _, v := range ports {
					r.PortRange[v] = struct{}{}
				}
			}
		}
		if rule.InboundTags != nil {
			if len(rule.InboundTags) == 0 {
				return nil, fmt.Errorf("the %dth routing rule: if set inbound tags then they cannot be empty", i+1)
			}
			r.InboundTags = make(map[string]struct{})
			for j, v := range rule.InboundTags {
				if v == "" {
					return nil, fmt.Errorf("the %dth routing rule: the %dth inbound tag is empty", i+1, j+1)
				}
				if r.HasInboundTag(v) {
					return nil, fmt.Errorf("the %dth routing rule: the %dth inbound tag is duplicated: %s", i+1, j+1, v)
				}
				r.InboundTags[v] = struct{}{}
			}
		}
		for j, v := range rule.OutboundTags {
			if v == "" {
				return nil, fmt.Errorf("the %dth routing rule: the %dth outbound tag is empty", i+1, j+1)
			}
			if r.HasOutboundTag(v) {
				return nil, fmt.Errorf("the %dth routing rule: the %dth outbound tag is duplicated: %s", i+1, j+1, v)
			}
			r.OutboundTags[v] = struct{}{}
		}
		if len(r.OutboundTags) == 0 {
			return nil, fmt.Errorf("the %d routing rule: outbound tags are empty", i+1)
		}
		if rule.IncludeHosts != nil {
			if len(rule.IncludeHosts) == 0 {
				return nil, fmt.Errorf("the %dth routing rule: if set hosts then they cannot be empty", i+1)
			}
			m, err := BuildHostMatcher(rule.IncludeHosts, h)
			if err != nil {
				return nil, fmt.Errorf("the %dth routing rule: %w", i+1, err)
			}
			r.IncludeMatcher = m
		}
		if rule.ExcludeHosts != nil {
			if len(rule.ExcludeHosts) == 0 {
				return nil, fmt.Errorf("the %dth routing rule: if set hosts then they cannot be empty", i+1)
			}
			m, err := BuildHostMatcher(rule.ExcludeHosts, h)
			if err != nil {
				return nil, fmt.Errorf("the %dth routing rule: %w", i+1, err)
			}
			r.ExcludeMatcher = m
		}
		routing.Rules = append(routing.Rules, r)
	}
	return routing, nil
}

type HostMatcher struct {
	N4              []*net.IPNet
	N6              []*net.IPNet
	A4              []*netip.Addr
	A6              []*netip.Addr
	Domains         []string
	GeoSiteMatchers []*geo.GeoSiteMatcher
}

func (m *HostMatcher) matchGeoSite(a *common.NetAddr) bool {
	if len(m.GeoSiteMatchers) > 0 && a.IsFQDN() {
		for _, v := range m.GeoSiteMatchers {
			if v.Match(a.FQDN) {
				return true
			}
		}
	}
	return false
}

func (m *HostMatcher) Match(a *common.NetAddr) bool {
	if m.matchGeoSite(a) {
		return true
	}
	if a.IsIP() {
		var (
			ipNets  []*net.IPNet
			ipAddrs []*netip.Addr
		)
		if a.IsIPv6() {
			ipNets = m.N6
			ipAddrs = m.A6
		} else {
			ipNets = m.N4
			ipAddrs = m.A4
		}
		if len(ipAddrs) > 0 {
			addr := *a.IP
			left, right := 0, len(ipAddrs)-1
			for left <= right {
				mid := (left + right) / 2
				v := ipAddrs[mid].Compare(addr)
				if v == 0 {
					return true
				} else if v < 0 {
					left = mid + 1
				} else {
					right = mid - 1
				}
			}
		}
		if len(ipNets) > 0 {
			ip := a.IP.AsSlice()
			left, right := 0, len(ipNets)-1
			for left <= right {
				mid := (left + right) / 2
				if ipNets[mid].Contains(ip) {
					return true
				} else if bytes.Compare(ipNets[mid].IP, ip) < 0 {
					left = mid + 1
				} else {
					right = mid - 1
				}
			}
		}
	} else {
		for _, v := range m.Domains {
			if v[0] == '.' && strings.HasSuffix(a.FQDN, v) {
				return true
			} else if v == a.FQDN || strings.HasSuffix(a.FQDN, "."+v) {
				return true
			}
		}
	}
	return false
}

func (m *HostMatcher) Sort() {
	// Sort the IPNets, so we can do binary search later.
	if len(m.N4) > 0 {
		sort.Slice(m.N4, func(i, j int) bool {
			return bytes.Compare(m.N4[i].IP, m.N4[j].IP) < 0
		})
	}
	if len(m.N6) > 0 {
		sort.Slice(m.N6, func(i, j int) bool {
			return bytes.Compare(m.N6[i].IP, m.N6[j].IP) < 0
		})
	}
	if len(m.A4) > 0 {
		sort.Slice(m.A4, func(i, j int) bool {
			return m.A4[i].Compare(*m.A4[j]) < 0
		})
	}
	if len(m.A6) > 0 {
		sort.Slice(m.A6, func(i, j int) bool {
			return m.A6[i].Compare(*m.A6[j]) < 0
		})
	}
}

func (m *HostMatcher) Merge(other *HostMatcher) {
	m.N4 = append(m.N4, other.N4...)
	m.N6 = append(m.N6, other.N6...)
	m.A4 = append(m.A4, other.A4...)
	m.A6 = append(m.A6, other.A6...)
	m.Domains = append(m.Domains, other.Domains...)
	m.GeoSiteMatchers = append(m.GeoSiteMatchers, other.GeoSiteMatchers...)
}

// host could be CIDR, domain or IP string
func (m *HostMatcher) AddHost(host string) error {
	if strings.Contains(host, "/") {
		_, ipNet, err := net.ParseCIDR(host)
		if err != nil {
			return err
		}
		if ipNet.IP.To4() != nil {
			m.N4 = append(m.N4, ipNet)
		} else {
			m.N6 = append(m.N6, ipNet)
		}
	} else {
		var prefix string
		if len(host) > 0 && host[0] == '.' {
			prefix = "."
			host = host[1:]
		}
		host, ipAddr, err := common.ParseHost(host)
		if err != nil {
			return err
		}
		if ipAddr != nil {
			if ipAddr.Is4() {
				m.A4 = append(m.A4, ipAddr)
			} else {
				m.A6 = append(m.A6, ipAddr)
			}
		} else {
			m.Domains = append(m.Domains, prefix+host)
		}
	}
	return nil
}

func BuildHostMatcher(hosts []string, h *geoHandle) (*HostMatcher, error) {
	for i := range hosts {
		hosts[i] = strings.ToLower(hosts[i])
	}
	m := &HostMatcher{}
	hostMap := make(map[string]int)
	var privateMatcher *HostMatcher
	for i, v := range hosts {
		if j := hostMap[v]; j > 0 {
			return nil, fmt.Errorf("the %dth host is duplicated by the one at position %d: %s", i+1, j, v)
		}
		hostMap[v] = i + 1
		// special
		if strings.HasPrefix(v, "geoip:") {
			k := v[6:]
			matcher, err := h.GetGeoIPMatcher(k)
			if err != nil {
				return nil, fmt.Errorf("the %dth host: %v", i+1, err)
			}
			m.Merge(matcher)
		} else if strings.HasPrefix(v, "geosite:") {
			k := v[8:]
			matcher, err := h.GetGeoSiteMatcher(k)
			if err != nil {
				return nil, fmt.Errorf("the %dth host: %v", i+1, err)
			}
			m.GeoSiteMatchers = append(m.GeoSiteMatchers, matcher)
		} else if v == "private" {
			// lazy init
			if privateMatcher == nil {
				privateMatcher = GetPrivateHostMatcher()
			}
			m.Merge(privateMatcher)
		} else {
			err := m.AddHost(v)
			if err != nil {
				return nil, fmt.Errorf("the %dth host %s is invalid: %w", i+1, v, err)
			}
		}
	}
	m.Sort()
	return m, nil
}

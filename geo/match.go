package geo

import (
	"errors"
	"regexp"
	"strings"
)

type geositeDomainType int

const (
	geositeDomainPlain geositeDomainType = iota
	geositeDomainRegex
	geositeDomainRoot
	geositeDomainFull
)

type geositeDomain struct {
	Type  geositeDomainType
	Value string
	Regex *regexp.Regexp
	Attrs map[string]bool
}

type GeoSiteMatcher struct {
	Domains []geositeDomain
	// Attributes are matched using "and" logic - if you have multiple attributes here,
	// a domain must have all of those attributes to be considered a match.
	Attrs []string
}

func (m *GeoSiteMatcher) match(domain geositeDomain, name string) bool {
	// Match attributes first
	if len(m.Attrs) > 0 {
		if len(domain.Attrs) == 0 {
			return false
		}
		for _, attr := range m.Attrs {
			if !domain.Attrs[attr] {
				return false
			}
		}
	}
	switch domain.Type {
	case geositeDomainPlain:
		return strings.Contains(name, domain.Value)
	case geositeDomainRegex:
		if domain.Regex != nil {
			return domain.Regex.MatchString(name)
		}
	case geositeDomainFull:
		return name == domain.Value
	case geositeDomainRoot:
		if name == domain.Value {
			return true
		}
		return strings.HasSuffix(name, "."+domain.Value)
	default:
		return false
	}
	return false
}

func (m *GeoSiteMatcher) Match(name string) bool {
	for _, domain := range m.Domains {
		if m.match(domain, name) {
			return true
		}
	}
	return false
}

func NewGeoSiteMatcher(list *GeoSite, attrs []string) (*GeoSiteMatcher, error) {
	domains := make([]geositeDomain, len(list.Domain))
	for i, domain := range list.Domain {
		switch domain.Type {
		case Domain_Plain:
			domains[i] = geositeDomain{
				Type:  geositeDomainPlain,
				Value: domain.Value,
				Attrs: domainAttributeToMap(domain.Attribute),
			}
		case Domain_Regex:
			regex, err := regexp.Compile(domain.Value)
			if err != nil {
				return nil, err
			}
			domains[i] = geositeDomain{
				Type:  geositeDomainRegex,
				Regex: regex,
				Attrs: domainAttributeToMap(domain.Attribute),
			}
		case Domain_Full:
			domains[i] = geositeDomain{
				Type:  geositeDomainFull,
				Value: domain.Value,
				Attrs: domainAttributeToMap(domain.Attribute),
			}
		case Domain_RootDomain:
			domains[i] = geositeDomain{
				Type:  geositeDomainRoot,
				Value: domain.Value,
				Attrs: domainAttributeToMap(domain.Attribute),
			}
		default:
			return nil, errors.New("invalid domain type")
		}
	}
	return &GeoSiteMatcher{
		Domains: domains,
		Attrs:   attrs,
	}, nil
}

func domainAttributeToMap(attrs []*Domain_Attribute) map[string]bool {
	m := make(map[string]bool)
	for _, attr := range attrs {
		// Supposedly there are also int attributes,
		// but nobody seems to use them, so we treat everything as boolean for now.
		m[attr.Key] = true
	}
	return m
}

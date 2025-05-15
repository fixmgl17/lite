package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"lite/common"
	"lite/tls"
	"net/http"
	"os"

	"github.com/pelletier/go-toml/v2"
)

type InboundConfig struct {
	Tag              string         `json:"tag" toml:"tag"`
	Listen           string         `json:"listen" toml:"listen"`
	Protocol         string         `json:"protocol" toml:"protocol"`
	ProtocolSettings map[string]any `json:"protocol_settings,omitempty" toml:"protocol_settings"`
	// Only for lite protocol
	Transport string `json:"transport" toml:"transport"`
	// Only for lite protocol
	TransportSettings map[string]any `json:"transport_settings,omitempty" toml:"transport_settings"`
	TLS               *tls.Config    `json:"tls,omitempty" toml:"tls"`
}

type OutboundConfig struct {
	Tag              string         `json:"tag" toml:"tag"`
	Server           string         `json:"server" toml:"server"`
	DNSResolve       dnsResolveEnum `json:"dns_resolve" toml:"dns_resolve"`
	DialMode         dnsResolveEnum `json:"dial_mode" toml:"dial_mode"`
	Protocol         string         `json:"protocol" toml:"protocol"`
	ProtocolSettings map[string]any `json:"protocol_settings,omitempty" toml:"protocol_settings"`
	// Only for lite protocol
	Transport string `json:"transport" toml:"transport"`
	// Only for lite protocol
	TransportSettings map[string]any `json:"transport_settings,omitempty" toml:"transport_settings"`
	TLS               *tls.Config    `json:"tls,omitempty" toml:"tls"`
}

type LogConfig struct {
	Level   string `json:"level" toml:"level"`
	Output  string `json:"output" toml:"output"`
	MaxSize string `json:"max_size" toml:"max_size"`
}

type APIConfig struct {
	Listen string `json:"listen" toml:"listen"`
	Token  string `json:"token" toml:"token"`
	TLS    *tls.Config
}

type DNSConfig struct {
	TTL       string `json:"ttl,omitempty" toml:"ttl"`
	ServerURL string `json:"server_url,omitempty" toml:"server"`
}

type RoutingRuleConfig struct {
	InboundTags  []string    `json:"inbound_tags,omitempty" toml:"inbound_tags"`
	OutboundTags []string    `json:"outbound_tags" toml:"outbound_tags"`
	TimeRange    string      `json:"time_range,omitempty" toml:"time_range"`
	RequireIPv6  bool        `json:"require_ipv6,omitempty" toml:"require_ipv6"`
	Network      networkEnum `json:"network,omitempty" toml:"network"`
	PortRange    string      `json:"port_range,omitempty" toml:"port_range"`
	IncludeHosts []string    `json:"include_hosts,omitempty" toml:"include_hosts"`
	ExcludeHosts []string    `json:"exclude_hosts,omitempty" toml:"exclude_hosts"`
}

type GeoConfig struct {
	UpdateInterval string `json:"update_interval" toml:"update_interval"`
	IPURL          string `json:"ip_url" toml:"ip_url"`
	SiteURL        string `json:"site_url" toml:"site_url"`
}

type RoutingConfig struct {
	Rules []RoutingRuleConfig `json:"rules,omitempty" toml:"rules"`
}

type Config struct {
	AutoSystemProxy bool              `json:"auto_system_proxy" toml:"auto_system_proxy"`
	Log             *LogConfig        `json:"log" toml:"log"`
	API             *APIConfig        `json:"api" toml:"api"`
	DNS             *DNSConfig        `json:"dns" toml:"dns"`
	Geo             *GeoConfig        `json:"geo" toml:"geo"`
	Routing         *RoutingConfig    `json:"routing" toml:"routing"`
	Inbounds        []*InboundConfig  `json:"inbounds" toml:"inbounds"`
	Outbounds       []*OutboundConfig `json:"outbounds,omitempty" toml:"outbounds"`
}

func (cfg *Config) FillDefault() *Config {
	if cfg.Log == nil {
		cfg.Log = &LogConfig{}
	}
	for i := range cfg.Inbounds {
		if cfg.Inbounds[i] == nil {
			cfg.Inbounds[i] = &InboundConfig{}
		}
		inbound := cfg.Inbounds[i]
		if inbound.ProtocolSettings == nil {
			inbound.ProtocolSettings = map[string]any{}
		}
		if inbound.TransportSettings == nil {
			inbound.TransportSettings = map[string]any{}
		}
	}
	for i := range cfg.Outbounds {
		if cfg.Outbounds[i] == nil {
			cfg.Outbounds[i] = &OutboundConfig{}
		}
		outbound := cfg.Outbounds[i]
		if outbound.ProtocolSettings == nil {
			outbound.ProtocolSettings = map[string]any{}
		}
		if outbound.TransportSettings == nil {
			outbound.TransportSettings = map[string]any{}
		}
	}
	if cfg.DNS == nil {
		cfg.DNS = &DNSConfig{}
	}
	if cfg.Routing == nil {
		cfg.Routing = &RoutingConfig{}
	}
	if cfg.Geo == nil {
		cfg.Geo = &GeoConfig{}
	}
	return cfg
}

func ReadConfig(r io.Reader) (*Config, error) {
	var buf bytes.Buffer
	r = io.TeeReader(r, &buf)
	var cfg Config
	err := toml.NewDecoder(r).Decode(&cfg)
	if err == nil {
		return cfg.FillDefault(), nil
	}
	err2 := json.NewDecoder(io.MultiReader(&buf, r)).Decode(&cfg)
	if err2 == nil {
		return cfg.FillDefault(), nil
	}
	return nil, fmt.Errorf("failed to read config as toml: %v ; failed to read config as json: %v", err, err2)
}

func ReadConfigFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadConfig(f)
}

func ReadConfigURL(url string) (*Config, error) {
	client := &http.Client{
		Transport: http.DefaultTransport.(*http.Transport).Clone(),
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", common.DefaultUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP server returned with non-OK code %d", resp.StatusCode)
	}
	return ReadConfig(resp.Body)
}

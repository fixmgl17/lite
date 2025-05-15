package app

import (
	"fmt"
	"lite/common"
	"lite/lite"
	"lite/lite/http/websocket"
	"lite/tls"
	"net/url"
	"strconv"
	"strings"
)

/*
lite://<id-text>@<server>:<server_port>
    ?transport=<tcp|websocket>&
    host=<host>&
    path=<path>&
    only_http_upgrade=<true|false>&
	early_data_header_name=<early_data_header_name>&
    server_name=<server_name>&
    fignerprint=<fignerprint>&
    cert_hash=<cert_hash>&
    insecure=<true|false>
    #<descriptive-text>
*/

func LiteLinkToOutboundConfig(link string) (*OutboundConfig, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	a, err := common.NewNetAddr("tcp", u.Host)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	cfg := &OutboundConfig{
		Tag:      u.Fragment,
		Server:   a.Address(),
		Protocol: "lite",
		ProtocolSettings: map[string]any{
			"user": map[string]any{
				"id": u.User.String(),
			},
		},
		Transport: q.Get("transport"),
	}
	if cfg.Transport == "websocket" {
		cfg.TransportSettings = map[string]any{
			"host":                   q.Get("host"),
			"path":                   q.Get("path"),
			"only_http_upgrade":      q.Get("only_http_upgrade") == "true",
			"early_data_header_name": q.Get("early_data_header_name"),
		}
	}
	if q.Get("insecure") == "true" || q.Get("server_name") != "" {
		cfg.TLS = &tls.Config{
			ServerName:      q.Get("server_name"),
			CertificateHash: q.Get("cert_hash"),
			Insecure:        q.Get("insecure") == "true",
			Fingerprint:     q.Get("fignerprint"),
		}
	}
	return cfg, nil
}

func LiteOutboundConfigToLink(cfg *OutboundConfig) (string, error) {
	u := &url.URL{
		Scheme:   "lite",
		Host:     cfg.Server,
		Fragment: cfg.Tag,
	}
	q := make(url.Values)
	q.Set("transport", cfg.Transport)
	if cfg.Transport == "websocket" && cfg.TransportSettings != nil {
		var layerConf websocket.LayerConfig
		err := common.ConvertStruct(cfg.TransportSettings, &layerConf)
		if err != nil {
			return "", err
		}
		q.Set("host", layerConf.Host)
		q.Set("path", layerConf.Path)
		q.Set("only_http_upgrade", strconv.FormatBool(layerConf.OnlyHTTPUpgrade))
		q.Set("early_data_header_name", layerConf.EarlyDataHeaderName)
	}
	if cfg.TLS != nil {
		q.Set("server_name", cfg.TLS.ServerName)
		q.Set("fignerprint", cfg.TLS.Fingerprint)
		q.Set("cert_hash", cfg.TLS.CertificateHash)
		q.Set("insecure", strconv.FormatBool(cfg.TLS.Insecure))
	}
	removeEmptyKey(q)
	u.RawQuery = q.Encode()
	link := u.String()
	if cfg.ProtocolSettings != nil {
		var dialerConf lite.DialerConfig
		err := common.ConvertStruct(cfg.ProtocolSettings, &dialerConf)
		if err != nil {
			return "", err
		}
		link = strings.Replace(link, "lite://",
			"lite://"+strings.TrimSuffix(url.UserPassword(dialerConf.User.ID, "").String(), ":")+"@", 1)
	}
	return link, nil
}

func LiteInboundConfigToLink(cfg *InboundConfig) (string, error) {
	u := &url.URL{
		Scheme:   "lite",
		Host:     cfg.Listen,
		Fragment: cfg.Tag,
	}
	q := make(url.Values)
	q.Set("transport", cfg.Transport)
	if cfg.Transport == "websocket" && cfg.TransportSettings != nil {
		var processorConf websocket.ProcessorConfig
		err := common.ConvertStruct(cfg.TransportSettings, &processorConf)
		if err != nil {
			return "", err
		}
		q.Set("host", processorConf.Host)
		q.Set("path", processorConf.Path)
		q.Set("only_http_upgrade", "true")
		q.Set("early_data_header_name", processorConf.EarlyDataHeaderName)
	}
	if cfg.TLS != nil {
		q.Set("server_name", cfg.TLS.ServerName)
		q.Set("fignerprint", cfg.TLS.Fingerprint)
		q.Set("cert_hash", cfg.TLS.CertificateHash)
		q.Set("insecure", fmt.Sprint(cfg.TLS.Insecure))
	}
	removeEmptyKey(q)
	u.RawQuery = q.Encode()
	link := u.String()
	if cfg.ProtocolSettings != nil {
		var serverConf lite.ServerConfig
		err := common.ConvertStruct(cfg.ProtocolSettings, &serverConf)
		if err != nil {
			return "", err
		}
		if len(serverConf.Users) > 0 {
			link = strings.Replace(link, "lite://",
				"lite://"+strings.TrimSuffix(url.UserPassword(serverConf.Users[0].ID, "").String(), ":")+"@", 1)
		}
	}
	return link, nil
}

func removeEmptyKey(q url.Values) {
	for k := range q {
		if q.Get(k) == "" {
			q.Del(k)
		}
	}
}

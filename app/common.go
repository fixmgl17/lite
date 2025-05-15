package app

import (
	"lite/common"
	"lite/lite/http/websocket"
	"lite/tls"
	"net"
	"net/http"
	"strings"
)

func parseListenAddr(s string) (*common.NetAddr, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	if host == "" {
		host = "0.0.0.0"
	}
	return common.NewNetAddr("tcp", net.JoinHostPort(host, port))
}

func printTLSCertInfo(prefix string, config *tls.Config) {
	if config == nil {
		return
	}
	certs, err := config.GetCertificates()
	if err != nil {
		logger.Error(prefix, err)
	}
	for _, cert := range certs {
		san := []string{}
		san = append(san, cert.DNSNames...)
		for _, ip := range cert.IPAddresses {
			san = append(san, ip.String())
		}
		logger.Infof(prefix+"SAN=%s  Issuer=%s  Validity Period=%s - %s", strings.Join(san, ", "), cert.Issuer, cert.NotBefore, cert.NotAfter)
	}
}

func joinIPList(ipList []net.IP, sep string) string {
	switch len(ipList) {
	case 0:
		return "<nil>"
	case 1:
		return ipList[0].String()
	}
	var builder strings.Builder
	builder.WriteString(ipList[0].String())
	for _, ip := range ipList[1:] {
		builder.WriteString(sep)
		builder.WriteString(ip.String())
	}
	return builder.String()
}

func fillDialerTLSConfig(config *tls.Config, serverAddr *common.NetAddr) {
	if config == nil {
		return
	}
	if config.ServerName == "" {
		config.ServerName = serverAddr.Hostname()
	}
	if config.Fingerprint == "" {
		config.Fingerprint = "chrome"
	}
}

func fillWebsocketConfig(config *websocket.LayerConfig, serverAddr *common.NetAddr, tlsConfig *tls.Config) {
	if config.Headers == nil {
		config.Headers = map[string]string{}
	}
	if config.Host == "" {
		if tlsConfig != nil && tlsConfig.ServerName != "" {
			config.Host = tlsConfig.ServerName
		} else {
			if serverAddr.Port == 80 || serverAddr.Port == 443 {
				config.Host = serverAddr.Hostname()
			} else {
				config.Host = serverAddr.Address()
			}
		}
	}
	header := make(http.Header)
	for k, v := range config.Headers {
		header.Set(k, v)
	}
	defaultHeader := map[string]string{
		"Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
		"User-Agent":      common.DefaultUserAgent,
		"Cache-Control":   "no-cache",
		"Sec-Gpc":         "1",
	}
	if tlsConfig == nil {
		defaultHeader["Origin"] = "http://" + config.Host
	} else {
		defaultHeader["Origin"] = "https://" + config.Host
	}
	for k, v := range defaultHeader {
		if header.Get(k) == "" {
			header.Set(k, v)
		}
	}
	for k := range header {
		config.Headers[k] = header.Get(k)
	}
}

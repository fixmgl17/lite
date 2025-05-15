package tls

import (
	"net"

	utls "github.com/refraction-networking/utls"
)

type Layer struct {
	TLSConfig     *utls.Config
	ClientHelloID *utls.ClientHelloID
	NextProtos    []string
}

func NewLayer(tlsConfig *utls.Config, clientHelloID *utls.ClientHelloID) *Layer {
	tlsConfig.MinVersion = utls.VersionTLS13
	return &Layer{
		TLSConfig:     tlsConfig,
		ClientHelloID: clientHelloID,
		NextProtos:    tlsConfig.NextProtos,
	}
}

func (l *Layer) Client(c net.Conn) net.Conn {
	l.TLSConfig.NextProtos = l.NextProtos
	if l.ClientHelloID == nil {
		return utls.Client(c, l.TLSConfig)
	}
	// Ref: https://github.com/XTLS/Xray-core/blob/a608c5a1dbfa59b8328ac5d0363f360b2fd3bebe/transport/internet/tls/tls.go#L101
	utlsConn := utls.UClient(c, l.TLSConfig, *l.ClientHelloID)
	if err := utlsConn.BuildHandshakeState(); err != nil {
		panic(err)
	}
	// Iterate over extensions and check for utls.ALPNExtension
	hasALPNExtension := false
	for _, extension := range utlsConn.Extensions {
		if alpn, ok := extension.(*utls.ALPNExtension); ok {
			hasALPNExtension = true
			alpn.AlpnProtocols = l.NextProtos
			break
		}
	}
	if !hasALPNExtension { // Append extension if doesn't exists
		utlsConn.Extensions = append(utlsConn.Extensions, &utls.ALPNExtension{AlpnProtocols: l.NextProtos})
	}
	// Rebuild the client hello and do the handshake
	if err := utlsConn.BuildHandshakeState(); err != nil {
		panic(err)
	}
	return utlsConn
}

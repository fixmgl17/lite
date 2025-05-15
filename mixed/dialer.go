package mixed

import (
	"context"
	"errors"
	"lite/common"
	"lite/lite/tcp"
	"lite/mixed/http"
	"lite/mixed/socks5"
	"net"
)

type Dialer struct {
	protocol   string
	config     DialerConfig
	serverAddr *common.NetAddr
	dialer     *tcp.Dialer
}

// Protocol must be "http" or "socks5"
func NewDialer(protocol string, addr *common.NetAddr, config DialerConfig) (*Dialer, error) {
	switch protocol {
	case http.Protocol, socks5.Protocol:
	default:
		return nil, errors.New("unknown protocol " + protocol)
	}
	return &Dialer{
		protocol:   protocol,
		config:     config,
		serverAddr: addr,
		dialer:     tcp.NewDialer(nil),
	}, nil
}

func (d *Dialer) Protocol() string {
	return d.protocol
}

func (d *Dialer) User() (username, password string) {
	return d.config.Username, d.config.Password
}

func (d *Dialer) SetDialTCPFunc(fn func(ctx context.Context, addr *common.NetAddr) (net.Conn, error)) {
	d.dialer.SetDialTCPFunc(fn)
}

func (d *Dialer) DialTCP(ctx context.Context, addr *common.NetAddr) (net.Conn, error) {
	var (
		rawConn net.Conn
		err     error
	)
	rawConn, err = d.dialer.DialTCP(ctx, d.serverAddr)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			rawConn.Close()
		}
	}()
	switch d.protocol {
	case socks5.Protocol:
		return socks5.DialTCP(rawConn, addr, d.config.Username, d.config.Password)
	case http.Protocol:
		return http.DialTCP(rawConn, addr, d.config.Username, d.config.Password)
	default:
		return nil, errors.New("invalid protocol " + d.protocol)
	}
}

func (d *Dialer) DialUDP(ctx context.Context, addr *common.NetAddr) (net.PacketConn, error) {
	switch d.protocol {
	case socks5.Protocol:
		rawConn, err := d.dialer.DialTCP(ctx, d.serverAddr)
		if err != nil {
			return nil, err
		}
		conn, err := socks5.DialUDP(rawConn, addr, d.config.Username, d.config.Password)
		if err != nil {
			rawConn.Close()
		}
		return conn, err
	case http.Protocol:
		return nil, errors.New("http proxy does not support udp")
	default:
		return nil, errors.New("invalid protocol " + d.protocol)
	}
}

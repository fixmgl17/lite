package app

import (
	"context"
	"fmt"
	"lite/common"
	"lite/dns"
	"lite/lite"
	"lite/lite/http/websocket"
	"lite/lite/tcp"
	"lite/mixed"
	"net"
)

const (
	DialModeAuto = DNSResolveAuto
	DialMode46   = DNSResolve46
	DialMode64   = DNSResolve64
	DialMode4    = DNSResolve4
	DialMode6    = DNSResolve6
)

type Outbound struct {
	Tag string

	internalTag     string
	dialTCPInternal func(ctx context.Context, addr *common.NetAddr) (net.Conn, error)
	dialUDPInternal func(ctx context.Context, addr *common.NetAddr) (net.PacketConn, error)

	ServerAddr *common.NetAddr

	DialMode dnsResolveEnum

	DNSResolve dnsResolveEnum

	Resolver dns.Resolver

	mixedDialer *mixed.Dialer
	liteDialer  *lite.Dialer
}

func (ob *Outbound) Info() (protocol string, transport string) {
	if ob.internalTag != "" {
		return ob.internalTag, ""
	}
	if ob.liteDialer != nil {
		return ob.liteDialer.Protocol(), ob.liteDialer.Transport()
	}
	return ob.mixedDialer.Protocol(), ""
}

func (ob *Outbound) InternalTag() string {
	return ob.internalTag
}

type dialResult struct {
	Conn net.Conn
	Err  error
}

func (ob *Outbound) DialTCPWithoutProxy(ctx context.Context, addr *common.NetAddr) (c net.Conn, err error) {
	var ipv4, ipv6 net.IP
	if addr.IsIPv4() {
		ipv4 = addr.IP.AsSlice()
	} else if addr.IsIPv6() {
		ipv6 = addr.IP.AsSlice()
	} else {
		var mode dnsResolveEnum
		switch ob.DialMode {
		case DialMode46, DialMode64, DialModeAuto:
			mode = DNSResolveAuto
		default:
			mode = ob.DialMode
		}
		ipv4, ipv6, err = LookupIPWithMode(ctx, ob.Resolver, mode, addr.FQDN)
		if err != nil {
			return nil, err
		}
	}
	if ipv4 != nil && ipv6 != nil {
		switch ob.DialMode {
		case DialMode46:
			c, err = tcp.Dial(ctx, common.JoinAddrPort(ipv4.String(), addr.Port))
			if err != nil {
				c, err = tcp.Dial(ctx, common.JoinAddrPort(ipv6.String(), addr.Port))
			}
		case DialMode64:
			c, err = tcp.Dial(ctx, common.JoinAddrPort(ipv6.String(), addr.Port))
			if err != nil {
				c, err = tcp.Dial(ctx, common.JoinAddrPort(ipv4.String(), addr.Port))
			}
		case DialModeAuto:
			ch := make(chan dialResult, 2)
			go func() {
				conn, err := tcp.Dial(ctx, common.JoinAddrPort(ipv4.String(), addr.Port))
				ch <- dialResult{Conn: conn, Err: err}
			}()
			go func() {
				conn, err := tcp.Dial(ctx, common.JoinAddrPort(ipv4.String(), addr.Port))
				ch <- dialResult{Conn: conn, Err: err}
			}()
			if r := <-ch; r.Err == nil {
				go func() {
					r2 := <-ch
					if r2.Conn != nil {
						_ = r2.Conn.Close()
					}
				}()
				c = r.Conn
			} else {
				r2 := <-ch
				c, err = r2.Conn, r2.Err
			}
		default:
			panic("impossible")
		}
	} else if ipv4 != nil {
		c, err = tcp.Dial(ctx, common.JoinAddrPort(ipv4.String(), addr.Port))
	} else {
		// ipv6
		c, err = tcp.Dial(ctx, common.JoinAddrPort(ipv6.String(), addr.Port))
	}
	if c != nil {
		c = common.NewBufferedConnSize(c, 4*1024)
	}
	return c, err
}

func (ob *Outbound) DialTCP(ctx context.Context, addr *common.NetAddr) (net.Conn, error) {
	if ob.dialTCPInternal != nil {
		return ob.dialTCPInternal(ctx, addr)
	}
	if ob.liteDialer != nil {
		return ob.liteDialer.DialTCP(ctx, addr)
	}
	return ob.mixedDialer.DialTCP(ctx, addr)
}

func (ob *Outbound) DialUDP(ctx context.Context, addr *common.NetAddr) (net.PacketConn, error) {
	if ob.dialUDPInternal != nil {
		return ob.dialUDPInternal(ctx, addr)
	}
	if ob.liteDialer != nil {
		return ob.liteDialer.DialUDP(ctx, addr)
	}
	return ob.mixedDialer.DialUDP(ctx, addr)
}

func (ob *Outbound) Close() error {
	return nil
}

func BuildOutbound(config *OutboundConfig) (*Outbound, error) {
	if config.DialMode == "" {
		config.DialMode = DialModeAuto
	}
	if config.Protocol == "" {
		config.Protocol = "direct"
	}
	if config.Transport == "" {
		config.Transport = "tcp"
	}
	switch config.DialMode {
	case DialModeAuto, DialMode46, DialMode64, DialMode4, DialMode6:
	default:
		return nil, fmt.Errorf("invalid dial mode: %s", config.DialMode)
	}
	switch config.Protocol {
	case "direct":
		return NewDirectOutbound(config.Tag, config.DialMode, config.DNSResolve), nil
	case "block":
		config.Tag = BlockOutboundTag
		return NewBlockOutbound(), nil
	}
	switch config.Tag {
	case "direct", "block":
		return nil, fmt.Errorf("only direct/block outbound tag can be set as direct/block: %s ", config.Protocol)
	}
	var err error
	ob := &Outbound{
		Tag:        config.Tag,
		DialMode:   config.DialMode,
		DNSResolve: config.DNSResolve,
	}
	ob.ServerAddr, err = common.NewNetAddr("tcp", config.Server)
	if err != nil {
		return nil, err
	}
	switch config.Protocol {
	case "http", "socks5":
		var dialerConf mixed.DialerConfig
		err = common.ConvertStruct(config.ProtocolSettings, &dialerConf)
		if err != nil {
			return nil, err
		}
		ob.mixedDialer, err = mixed.NewDialer(config.Protocol, ob.ServerAddr, dialerConf)
		if ob.mixedDialer != nil {
			ob.mixedDialer.SetDialTCPFunc(ob.DialTCPWithoutProxy)
		}
	case "lite":
		var dialerConf lite.DialerConfig
		err = common.ConvertStruct(config.ProtocolSettings, &dialerConf)
		if err != nil {
			return nil, err
		}
		dialer, err := lite.NewDialer(ob.ServerAddr, dialerConf)
		if err != nil {
			return nil, err
		}
		fillDialerTLSConfig(config.TLS, ob.ServerAddr)
		switch config.Transport {
		case "tcp":
			err = dialer.SetTCPTransport(config.TLS)
		case "websocket":
			var layerConf websocket.LayerConfig
			err = common.ConvertStruct(config.TransportSettings, &layerConf)
			if err != nil {
				return nil, err
			}
			fillWebsocketConfig(&layerConf, ob.ServerAddr, config.TLS)
			err = dialer.SetWebsocketTransport(config.TLS, layerConf)
		default:
			err = fmt.Errorf("invalid transport for lite protocol: %s", config.Transport)
		}
		if err != nil {
			return nil, err
		}
		ob.liteDialer = dialer
		ob.liteDialer.SetDialTCPFunc(ob.DialTCPWithoutProxy)
	default:
		err = fmt.Errorf("invalid inbound protocol: %s", config.Protocol)
	}
	if err != nil {
		return nil, err
	}
	return ob, nil
}

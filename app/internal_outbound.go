package app

import (
	"context"
	"errors"
	"lite/common"
	"net"
)

var ErrBlockOutbound = errors.New("block")

const (
	DirectOutboundTag = "direct"
	BlockOutboundTag  = "block"
)

func NewBlockOutbound() *Outbound {
	return &Outbound{
		Tag:         BlockOutboundTag,
		internalTag: BlockOutboundTag,
		dialTCPInternal: func(ctx context.Context, addr *common.NetAddr) (net.Conn, error) {
			return nil, ErrBlockOutbound
		},
		dialUDPInternal: func(ctx context.Context, addr *common.NetAddr) (net.PacketConn, error) {
			return nil, ErrBlockOutbound
		},
	}
}

func NewDirectOutbound(tag string, dialMode, dnsResolve dnsResolveEnum) *Outbound {
	if tag == "" {
		tag = DirectOutboundTag
	}
	ob := &Outbound{
		Tag:         tag,
		internalTag: DirectOutboundTag,
		DialMode:    dialMode,
		DNSResolve:  dnsResolve,
	}
	ob.dialTCPInternal = ob.DialTCPWithoutProxy
	ob.dialUDPInternal = func(ctx context.Context, addr *common.NetAddr) (net.PacketConn, error) {
		udpConn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return nil, err
		}
		return &udpConnPacketWrapper{
			UDPConn: udpConn,
			LookupIP: func(host string) (net.IP, error) {
				ipv4, ipv6, err := LookupIPWithMode(ctx, ob.Resolver, ob.DialMode, host)
				if err != nil {
					return nil, err
				}
				if ipv4 != nil {
					return ipv4, nil
				}
				return ipv6, nil
			},
		}, nil
	}
	return ob
}

var (
	_ net.PacketConn = (*udpConnPacketWrapper)(nil)
)

type udpConnPacketWrapper struct {
	*net.UDPConn
	LookupIP func(host string) (net.IP, error)
}

func (c *udpConnPacketWrapper) WriteTo(b []byte, addr net.Addr) (int, error) {
	var udpAddr *net.UDPAddr
	switch addr := addr.(type) {
	case *net.UDPAddr:
		udpAddr = addr
	default:
		netAddr, err := common.ConvertAddr(addr)
		if err != nil {
			return 0, err
		}
		udpAddr = &net.UDPAddr{
			Port: int(netAddr.Port),
		}
		if netAddr.IsIP() {
			udpAddr.IP = netAddr.IP.AsSlice()
		} else {
			ip, err := c.LookupIP(netAddr.FQDN)
			if err != nil {
				return 0, err
			}
			udpAddr.IP = ip
		}
	}
	return c.UDPConn.WriteTo(b, udpAddr)
}

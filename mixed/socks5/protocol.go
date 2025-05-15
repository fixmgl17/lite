package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"lite/common"
	"net"
)

const Protocol = "socks5"

const (
	Version  = 0x05
	Reserved = 0x00
)

const (
	MethodNoAuth           = 0x00
	MethodUsernamePassword = 0x02
	MethodNoAcceptable     = 0xFF
)

const (
	AddressIPv4 = 0x01
	AddressFQDN = 0x03
	AddressIPv6 = 0x04
)

const (
	CommandConnect      = 0x01
	CommandBind         = 0x02
	CommandUDPAssociate = 0x03
)

const (
	ReplySucceeded               = 0x00
	ReplyGeneralFailure          = 0x01
	ReplyConnectionNotAllowed    = 0x02
	ReplyNetworkUnreachable      = 0x03
	ReplyHostUnreachable         = 0x04
	ReplyConnectionRefused       = 0x05
	ReplyTTLExpired              = 0x06
	ReplyCommandNotSupported     = 0x07
	ReplyAddressTypeNotSupported = 0x08
)

const (
	// Ref: https://en.wikipedia.org/wiki/User_Datagram_Protocol#UDP_datagram_structure
	MaxUDPPayloadSize = 65507
)

// +----+----------+----------+
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 1  |    1     | 1 to 255 |
// +----+----------+----------+

func ReadVersionAndMethods(r io.Reader, buf []byte) ([]byte, error) {
	_ = buf[254]
	_, err := io.ReadFull(r, buf[:1])
	if err != nil {
		return nil, err
	}
	if buf[0] != Version {
		return nil, fmt.Errorf("wrong socks5 version: %d", buf[0])
	}
	_, err = io.ReadFull(r, buf[:1])
	if err != nil {
		return nil, err
	}
	nmethods := buf[0]
	if nmethods == 0 {
		return nil, errors.New("socks5 method count must be greater than 0")
	}
	_, err = io.ReadFull(r, buf[:nmethods])
	if err != nil {
		return nil, err
	}
	return buf[:nmethods], nil
}

// +----+--------+
// |VER | METHOD |
// +----+--------+
// | 1  |   1    |
// +----+--------+

// +----+------+----------+------+----------+
// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
// +----+------+----------+------+----------+
// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
// +----+------+----------+------+----------+

func WriteAuthUsernamePassword(w io.Writer, username, password string, buf []byte) error {
	_ = buf[519]
	buf = buf[:0]
	if len(username) > 255 {
		username = username[:255]
	}
	if len(password) > 255 {
		password = password[:255]
	}
	buf = append(buf, 0x01, byte(len(username)))
	buf = append(buf, username...)
	buf = append(buf, byte(len(password)))
	buf = append(buf, password...)
	_, err := w.Write(buf)
	return err
}

func ReadAuthUsernamePassword(r io.Reader, buf []byte) (username string, password string, err error) {
	_ = buf[254]
	_, err = io.ReadFull(r, buf[:1])
	if err != nil {
		return "", "", err
	}
	// https://datatracker.ietf.org/doc/html/rfc1929#section-2
	if buf[0] != 0x01 {
		return "", "", fmt.Errorf("wrong socks5 auth version of MethodUserPassword: %d", buf[0])
	}
	_, err = io.ReadFull(r, buf[:1])
	if err != nil {
		return "", "", err
	}
	ulen := buf[0]
	_, err = io.ReadFull(r, buf[:ulen])
	if err != nil {
		return "", "", err
	}
	username = string(buf[:ulen])
	_, err = io.ReadFull(r, buf[:1])
	if err != nil {
		return "", "", err
	}
	plen := buf[0]
	_, err = io.ReadFull(r, buf[:plen])
	if err != nil {
		return "", "", err
	}
	return username, string(buf[:plen]), nil
}

// +----+--------+
// |VER | STATUS |
// +----+--------+
// | 1  |   1    |
// +----+--------+

// Request
// +----+-----+-------+------+----------+----------+
// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+

func ReadRequest(r io.Reader, buf []byte) (*common.NetAddr, error) {
	_ = buf[254]
	_, err := io.ReadFull(r, buf[:1])
	if err != nil {
		return nil, err
	}
	if buf[0] != Version {
		return nil, fmt.Errorf("wrong socks5 version: %d", buf[0])
	}
	_, err = io.ReadFull(r, buf[:1])
	if err != nil {
		return nil, err
	}
	addr := &common.NetAddr{}
	cmd := buf[0]
	switch cmd {
	case CommandConnect:
		addr.SetNetwork("tcp")
	case CommandUDPAssociate:
		addr.SetNetwork("udp")
	case CommandBind:
		return nil, errors.New("not support bind command")
	default:
		return nil, fmt.Errorf("invalid command: %d", cmd)
	}
	_, err = io.ReadFull(r, buf[:1])
	if err != nil {
		return nil, err
	}
	if buf[0] != Reserved {
		return nil, fmt.Errorf("wrong reserved byte: %d", buf[0])
	}
	_, err = io.ReadFull(r, buf[:1])
	if err != nil {
		return nil, err
	}
	switch buf[0] {
	case AddressIPv4:
		_, err := io.ReadFull(r, buf[:4])
		if err != nil {
			return nil, err
		}
		addr.SetIPv4(buf[:4])
	case AddressIPv6:
		_, err := io.ReadFull(r, buf[:16])
		if err != nil {
			return nil, err
		}
		addr.SetIPv6(buf[:16])
	case AddressFQDN:
		_, err := io.ReadFull(r, buf[:1])
		if err != nil {
			return nil, err
		}
		fqdnLen := buf[0]
		if fqdnLen < 1 {
			return nil, fmt.Errorf("invalid domain length: %d", fqdnLen)
		}
		_, err = io.ReadFull(r, buf[:fqdnLen])
		if err != nil {
			return nil, err
		}
		addr.FQDN = string(buf[:fqdnLen])
		// compatible
		if ip := net.ParseIP(addr.FQDN); ip != nil {
			addr.FQDN = ""
			addr.SetIP(ip)
		}
	default:
		return nil, fmt.Errorf("invalid address type: %d", buf[0])
	}
	_, err = io.ReadFull(r, buf[:2])
	if err != nil {
		return nil, err
	}
	addr.Port = binary.BigEndian.Uint16(buf[:2])
	return addr, nil
}

func WriteRequest(w io.Writer, addr *common.NetAddr, buf []byte) error {
	// 1+1+1+1+256+2
	_ = buf[261]
	buf = buf[:0]
	// b := make([]byte, 0, 1+1+1+1+(1+255)+2)
	buf = append(buf, Version)
	if addr.IsTCP() {
		buf = append(buf, CommandConnect)
	} else if addr.IsUDP() {
		buf = append(buf, CommandUDPAssociate)
	} else {
		return fmt.Errorf("invalid network: %s", addr.Net)
	}
	buf = append(buf, Reserved)
	if addr.IsFQDN() {
		buf = append(buf, AddressFQDN)
		buf = append(buf, byte(len(addr.FQDN)))
		buf = append(buf, addr.FQDN...)
	} else if addr.IsIPv4() {
		buf = append(buf, AddressIPv4)
		a4 := addr.IP.As4()
		buf = append(buf, a4[:]...)
	} else if addr.IsIPv6() {
		buf = append(buf, AddressIPv6)
		a16 := addr.IP.As16()
		buf = append(buf, a16[:]...)
	} else {
		return fmt.Errorf("invalid address type: %s", addr.Address())
	}
	buf = binary.BigEndian.AppendUint16(buf, addr.Port)
	_, err := w.Write(buf)
	return err
}

// +----+-----+-------+------+----------+----------+
// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+

func ReadResponse(r io.Reader, buf []byte) (*common.NetAddr, error) {
	_ = buf[255]
	// b := make([]byte, 1<<8-1)
	_, err := io.ReadFull(r, buf[:1])
	if err != nil {
		return nil, err
	}
	if buf[0] != Version {
		return nil, fmt.Errorf("wrong socks5 version: %d", buf[0])
	}
	// reply byte
	_, err = io.ReadFull(r, buf[:1])
	if err != nil {
		return nil, err
	}
	switch buf[0] {
	case ReplySucceeded:
	case ReplyGeneralFailure:
		return nil, errors.New("socks5 server reply general failure")
	case ReplyConnectionNotAllowed:
		return nil, errors.New("socks5 server reply connection not allowed")
	case ReplyNetworkUnreachable:
		return nil, errors.New("socks5 server reply network unreachable")
	case ReplyHostUnreachable:
		return nil, errors.New("socks5 server reply host unreachable")
	case ReplyConnectionRefused:
		return nil, errors.New("socks5 server reply connection refused")
	case ReplyTTLExpired:
		return nil, errors.New("socks5 server reply ttl expired")
	case ReplyCommandNotSupported:
		return nil, errors.New("socks5 server reply command not supported")
	case ReplyAddressTypeNotSupported:
		return nil, errors.New("socks5 server reply address type not supported")
	default:
		return nil, fmt.Errorf("socks5 server reply unknown byte: %d", buf[0])
	}
	// reserved byte
	_, err = io.ReadFull(r, buf[:1])
	if err != nil {
		return nil, err
	}
	if buf[0] != Reserved {
		return nil, fmt.Errorf("invalid socks5 reserved byte when read response: %d", buf[0])
	}
	// address type
	_, err = io.ReadFull(r, buf[:1])
	if err != nil {
		return nil, err
	}
	addr := &common.NetAddr{}
	switch buf[0] {
	case AddressIPv4:
		_, err := io.ReadFull(r, buf[:4])
		if err != nil {
			return nil, err
		}
		addr.SetIPv4(buf[:4])
	case AddressIPv6:
		_, err := io.ReadFull(r, buf[:16])
		if err != nil {
			return nil, err
		}
		addr.SetIPv6(buf[:16])
	case AddressFQDN:
		_, err := io.ReadFull(r, buf[:1])
		if err != nil {
			return nil, err
		}
		fqdnLen := buf[0]
		if fqdnLen < 1 {
			return nil, fmt.Errorf("invalid domain length: %d", fqdnLen)
		}
		_, err = io.ReadFull(r, buf[:fqdnLen])
		if err != nil {
			return nil, err
		}
		addr.FQDN = string(buf[:fqdnLen])
	default:
		return nil, fmt.Errorf("invalid address type: %s", addr.Address())
	}
	_, err = io.ReadFull(r, buf[:2])
	if err != nil {
		return nil, err
	}
	addr.Port = binary.BigEndian.Uint16(buf[:2])
	return addr, nil
}

func WriteResponse(w io.Writer, addr *common.NetAddr, buf []byte) error {
	// 1 + 1 + 1 + 1 + 256 + 2
	_ = buf[:261]
	buf = buf[:0]
	buf = append(buf, Version, ReplySucceeded, Reserved)
	if addr.IsFQDN() {
		buf = append(buf, AddressFQDN)
		buf = append(buf, byte(len(addr.FQDN)))
		buf = append(buf, addr.FQDN...)
	} else if addr.IsIPv4() {
		buf = append(buf, AddressIPv4)
		a4 := addr.IP.As4()
		buf = append(buf, a4[:]...)
	} else if addr.IsIPv6() {
		buf = append(buf, AddressIPv6)
		a16 := addr.IP.As16()
		buf = append(buf, a16[:]...)
	} else {
		return fmt.Errorf("invalid address type: %s", addr.Address())
	}
	buf = binary.BigEndian.AppendUint16(buf, addr.Port)
	_, err := w.Write(buf)
	return err
}

type UDPPacket struct {
	// Reserved uint16 // 0x0000
	// Frag byte // 0x00
	*common.NetAddr
	Data []byte
}

var (
	_ net.Addr = (*UDPPacket)(nil)
)

// +----+------+------+----------+----------+----------+
// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +----+------+------+----------+----------+----------+
// | 2  |  1   |  1   | Variable |    2     | Variable |
// +----+------+------+----------+----------+----------+

func (p *UDPPacket) AppendTo(b []byte) ([]byte, error) {
	b = append(b, 0x00, 0x00, 0x00)
	if p.IsFQDN() {
		b = append(b, AddressFQDN)
		b = append(b, byte(len(p.FQDN)))
		b = append(b, p.FQDN...)
	} else if p.IsIPv4() {
		b = append(b, AddressIPv4)
		a4 := p.IP.As4()
		b = append(b, a4[:]...)
	} else if p.IsIPv6() {
		b = append(b, AddressIPv6)
		a16 := p.IP.As16()
		b = append(b, a16[:]...)
	} else {
		return nil, fmt.Errorf("invalid udp packet address: %s", p.Address())
	}
	b = binary.BigEndian.AppendUint16(b, p.Port)
	b = append(b, p.Data...)
	return b, nil
}

func ParseUDPPacket(b []byte) (*UDPPacket, error) {
	// 2+1+1+2+2+1
	if len(b) < 9 {
		return nil, errors.New("udp packet too short")
	}
	if b[0] != 0x00 || b[1] != 0x00 {
		return nil, fmt.Errorf("invalid reserved bytes: %02X", b[:2])
	}
	if b[2] != 0x00 {
		return nil, fmt.Errorf("invalid fragment: %d", b[2])
	}
	p := &UDPPacket{
		NetAddr: &common.NetAddr{
			Net: "udp",
		},
	}
	addressType := b[3]
	b = b[4:]
	switch addressType {
	case AddressIPv4:
		if len(b) < 4 {
			return nil, errors.New("udp packet too short")
		}
		p.SetIPv4(b[:4])
		b = b[4:]
	case AddressIPv6:
		if len(b) < 16 {
			return nil, errors.New("udp packet too short")
		}
		p.SetIPv6(b[:16])
		b = b[16:]
	case AddressFQDN:
		fqdnLen := b[0]
		if fqdnLen < 1 {
			return nil, fmt.Errorf("invalid domain length for udp packet: %d", fqdnLen)
		}
		if len(b) < 1+int(fqdnLen) {
			return nil, errors.New("udp packet too short")
		}
		p.FQDN = string(b[1 : 1+fqdnLen])
		b = b[1+fqdnLen:]
	default:
		return nil, fmt.Errorf("invalid udp packet address: %s", p.Address())
	}
	if len(b) < 2 {
		return nil, errors.New("udp packet too short")
	}
	p.Port = binary.BigEndian.Uint16(b[:2])
	p.Data = b[2:]
	return p, nil
}

func NewUDPPacket(addr net.Addr, data []byte) (*UDPPacket, error) {
	if len(data) > MaxUDPPayloadSize {
		return nil, fmt.Errorf("udp packet data length %d more than max udp payload length %d", len(data), MaxUDPPayloadSize)
	}
	switch addr := addr.(type) {
	case *net.UDPAddr:
		p := &UDPPacket{
			NetAddr: &common.NetAddr{
				Port: uint16(addr.Port),
				IP:   common.IPToAddr(addr.IP),
			},
			Data: data,
		}
		return p, nil
	}
	a, err := common.ConvertAddr(addr)
	if err != nil {
		return nil, err
	}
	if !a.IsUDP() {
		return nil, fmt.Errorf("address network is not udp: %s", a.Network())
	}
	p := &UDPPacket{
		NetAddr: a,
		Data:    data,
	}
	return p, nil
}

package lite

import (
	"encoding/binary"
	"fmt"
	"io"
	"lite/common"
	"net"
)

const Protocol = "lite"

const (
	CommandTCP = 1
	CommandUDP = 2
)

const (
	AddressIPv4 = 1
	AddressFQDN = 2
	AddressIPv6 = 3
)

const (
	// user [16]byte + CMD [1]byte + ATYP [1]byte + DST.ADDR [1<=n<=256]byte + DST.PORT [2]byte
	MaxRequestPayloadSize = 16 + 1 + 1 + 256 + 2

	// Ref: https://en.wikipedia.org/wiki/User_Datagram_Protocol#UDP_datagram_structure
	MaxUDPPayloadSize = 65507
)

// Request
//
// +------+-----+------+----------+----------+
// |  ID  | CMD | ATYP | DST.ADDR | DST.PORT |
// +------+-----+------+----------+----------+
// |  16  |  1  |  1   | Variable |    2     |
// +------+-----+------+----------+----------+
//
// DST.ADDR:
// IPv4:   4 bytes
// IPv6:   16 bytes
// Domain: 1 byte + x bytes
//
// Proxy UDP Packet
// +------+----------+----------+--------+----------+
// | ATYP | DST.ADDR | DST.PORT | Length | Payload  |
// +------+----------+----------+--------+----------+
// |  1   | Variable |    2     |   2    | Variable |
// +------+----------+----------+--------+----------+

// ATYP [1]byte + DST.ADDR [1<=n<=256]byte + DST.PORT [2]byte
//
// len(buf)>=255
func ReadAddr(r io.Reader, buf []byte) (*common.NetAddr, error) {
	_ = buf[254]
	a := &common.NetAddr{}
	_, err := io.ReadFull(r, buf[:1])
	if err != nil {
		return nil, err
	}
	switch buf[0] {
	case AddressIPv4:
		_, err := io.ReadFull(r, buf[:4])
		if err != nil {
			return nil, err
		}
		a.SetIPv4(buf[:4])
	case AddressIPv6:
		_, err := io.ReadFull(r, buf[:16])
		if err != nil {
			return nil, err
		}
		a.SetIPv6(buf[:16])
	case AddressFQDN:
		_, err = io.ReadFull(r, buf[:1])
		if err != nil {
			return nil, err
		}
		fqdnLen := buf[0]
		if fqdnLen < 1 {
			return nil, fmt.Errorf("invalid FQDN length %d", fqdnLen)
		}
		_, err := io.ReadFull(r, buf[:fqdnLen])
		if err != nil {
			return nil, err
		}
		a.FQDN = string(buf[:fqdnLen])
	default:
		return nil, fmt.Errorf("invalid address type %02X", buf[0])
	}
	_, err = io.ReadFull(r, buf[:2])
	if err != nil {
		return nil, err
	}
	a.Port = binary.BigEndian.Uint16(buf[:2])
	return a, nil
}

// | ATYP | DST.ADDR | DST.PORT |
func AppendAddr(b []byte, a *common.NetAddr) ([]byte, error) {
	if a.IsFQDN() {
		b = append(b, AddressFQDN)
		b = append(b, byte(len(a.FQDN)))
		b = append(b, []byte(a.FQDN)...)
	} else if a.IsIPv4() {
		b = append(b, AddressIPv4)
		a4 := a.IP.As4()
		b = append(b, a4[:]...)
	} else if a.IsIPv6() {
		b = append(b, AddressIPv6)
		a16 := a.IP.As16()
		b = append(b, a16[:]...)
	} else {
		return nil, fmt.Errorf("invalid address %s", a.Address())
	}
	b = binary.BigEndian.AppendUint16(b, a.Port)
	return b, nil
}

// ATYP [1]byte + DST.ADDR [1<=n<=256]byte + DST.PORT [2]byte + Length [2]byte + Payload
func ReadUDPPacket(r io.Reader, b []byte) (int, *common.NetAddr, error) {
	var buf []byte
	if len(b) > 255 {
		buf = b
	} else {
		buf = common.GetBuffer(256)
		defer common.PutBuffer(buf)
	}
	a, err := ReadAddr(r, buf)
	if err != nil {
		return 0, nil, err
	}
	a.SetNetwork("udp")
	_, err = io.ReadFull(r, buf[:2])
	if err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(buf[:2]))
	if n < 1 || n > MaxUDPPayloadSize {
		return 0, nil, fmt.Errorf("udp payload length must be in range [1, %d] but got %d", MaxUDPPayloadSize, n)
	}
	if n > len(b) {
		return 0, a, fmt.Errorf("%w: udp payload length %d exceeds buffer length %d", io.ErrShortBuffer, n, len(b))
	}
	_, err = io.ReadFull(r, b[:n])
	return n, a, err
}

// ATYP [1]byte + DST.ADDR [1<=n<=256]byte + DST.PORT [2]byte + Length [2]byte + Payload
func WriteUDPPacket(w io.Writer, addr net.Addr, b []byte, extra []byte) (int, error) {
	bn := len(b)
	if bn > MaxUDPPayloadSize {
		return 0, fmt.Errorf("buffer length %d is more than max udp payload length %d", len(b), MaxUDPPayloadSize)
	}
	a, err := common.ConvertAddr(addr)
	if err != nil {
		return 0, err
	}
	if !a.IsUDP() {
		return 0, fmt.Errorf("address network is not udp: %s", a.Network())
	}
	buf := common.GetBuffer(64 * 1024)[:0]
	defer common.PutBuffer(buf)
	if len(extra) > 0 {
		buf = append(buf, extra...)
	}
	buf, err = AppendAddr(buf, a)
	if err != nil {
		return 0, err
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(bn))
	buf = append(buf, b...)
	_, err = w.Write(buf)
	return bn, err
}

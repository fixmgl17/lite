package socks5

import (
	"errors"
	"fmt"
	"io"
	"lite/common"
	"net"
)

var (
	_ net.PacketConn = (*dialerPacketConn)(nil)
)

func clientHandshake(c net.Conn, addr *common.NetAddr, username, password string) (*common.NetAddr, error) {
	var buf []byte
	var clientMethod byte = MethodNoAuth
	if username != "" || password != "" {
		clientMethod = MethodUsernamePassword
		buf = common.GetBuffer(520)
	} else {
		buf = common.GetBuffer(270)
	}
	defer common.PutBuffer(buf)
	buf[0] = Version
	buf[1] = 1
	buf[2] = clientMethod
	_, err := c.Write(buf[:3])
	if err != nil {
		return nil, err
	}
	// ReadMethodReply
	_, err = io.ReadFull(c, buf[:2])
	if err != nil {
		return nil, err
	}
	if buf[0] != Version {
		return nil, fmt.Errorf("wrong socks5 version: %d", buf[0])
	}
	method := buf[1]
	if method == MethodNoAcceptable {
		return nil, errors.New("no acceptable method")
	}
	if method != clientMethod {
		return nil, errors.New("socks5 server reply method not match")
	}
	if method == MethodUsernamePassword {
		err = WriteAuthUsernamePassword(c, username, password, buf)
		if err != nil {
			return nil, err
		}
		// ReadAuthUsernamePasswordReply
		_, err = io.ReadFull(c, buf[:2])
		if err != nil {
			return nil, err
		}
		if buf[0] != 0x01 {
			return nil, fmt.Errorf("invalid socks5 auth version of MethodUserPassword: %d", buf[0])
		}
		if buf[1] != 0x00 {
			return nil, errors.New("socks5 server reply username or password not match")
		}
	}
	err = WriteRequest(c, addr, buf)
	if err != nil {
		return nil, err
	}
	return ReadResponse(c, buf)
}

func DialTCP(c net.Conn, addr *common.NetAddr, username, password string) (net.Conn, error) {
	_, err := clientHandshake(c, addr, username, password)
	if err != nil {
		return nil, fmt.Errorf("client handshake: %v", err)
	}
	return c, nil
}

func DialUDP(c net.Conn, addr *common.NetAddr, username, password string) (net.PacketConn, error) {
	rAddr, err := clientHandshake(c, addr, username, password)
	if err != nil {
		return nil, fmt.Errorf("client handshake: %v", err)
	}
	var udpAddr *net.UDPAddr
	if rAddr.IsFQDN() {
		var err error
		udpAddr, err = net.ResolveUDPAddr("udp", rAddr.Address())
		if err != nil {
			return nil, err
		}
	} else {
		udpAddr = &net.UDPAddr{
			IP:   rAddr.IP.AsSlice(),
			Port: int(rAddr.Port),
		}
	}
	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, err
	}
	return &dialerPacketConn{
		conn:    c,
		UDPConn: udpConn,
	}, nil
}

type dialerPacketConn struct {
	conn net.Conn
	*net.UDPConn
}

func (c *dialerPacketConn) Close() error {
	c.conn.Close()
	return c.UDPConn.Close()
}

func (c *dialerPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := b
	n, err := c.UDPConn.Read(buf)
	if err != nil {
		return 0, nil, err
	}
	p, err := ParseUDPPacket(buf[:n])
	if err != nil {
		return 0, nil, err
	}
	n = copy(b, p.Data)
	p.Data = nil
	return n, p.NetAddr, nil
}

func (c *dialerPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	p, err := NewUDPPacket(addr, b)
	if err != nil {
		return 0, err
	}
	buf := common.GetBuffer(64 * 1024)
	defer common.PutBuffer(buf)
	buf, err = p.AppendTo(buf[:0])
	if err != nil {
		return 0, err
	}
	_, err = c.UDPConn.Write(buf)
	if err != nil {
		return 0, err
	} else {
		return len(b), nil
	}
}

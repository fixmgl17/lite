package socks5

import (
	"errors"
	"fmt"
	"lite/common"
	"lite/common/proxy"
	"net"
	"time"
)

var (
	_ proxy.PacketConn = (*serverPacketConn)(nil)
)

func serverHandshake(c net.Conn, buf []byte, username, password string) (*common.NetAddr, error) {
	methods, err := ReadVersionAndMethods(c, buf)
	if err != nil {
		return nil, err
	}
	var requiredMethod byte = MethodNoAuth
	if username != "" || password != "" {
		requiredMethod = MethodUsernamePassword
	}
	var exist bool
	for _, m := range methods {
		if requiredMethod == m {
			exist = true
			break
		}
	}
	// https://datatracker.ietf.org/doc/html/rfc1928#section-3
	buf[0] = Version
	if !exist {
		buf[1] = MethodNoAcceptable
		c.Write(buf[:2])
		return nil, errors.New("no acceptable method")
	}
	buf[1] = requiredMethod
	_, err = c.Write(buf[:2])
	if err != nil {
		return nil, err
	}
	if requiredMethod == MethodUsernamePassword {
		reqUsername, reqPassword, err := ReadAuthUsernamePassword(c, buf)
		if err != nil {
			return nil, err
		}
		// WriteAuthUsernamePasswordReply
		buf[0] = 0x01 // specify auth version
		if reqUsername != username {
			err = errors.New("auth failed: wrong username " + username)
		}
		if reqPassword != password {
			err = errors.New("auth failed: wrong password " + password)
		}
		if err != nil {
			buf[1] = 0xFF
			c.Write(buf[:2])
			return nil, err
		}
		// https://datatracker.ietf.org/doc/html/rfc1929#section-2
		buf[1] = 0x00
		_, err = c.Write(buf[:2])
		if err != nil {
			return nil, err
		}
	}
	addr, err := ReadRequest(c, buf)
	if err != nil {
		return nil, err
	}
	return addr, nil
}

func ServeProxy(c net.Conn, username, password string) (net.Conn, proxy.PacketConn, *common.NetAddr, error) {
	buf := common.GetBuffer(270)
	defer common.PutBuffer(buf)
	addr, err := serverHandshake(c, buf, username, password)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("server hadnshake: %w", err)
	}
	laddr, err := common.NewNetAddr(c.LocalAddr().Network(), c.LocalAddr().String())
	if err != nil {
		return nil, nil, nil, err
	}
	var pc *serverPacketConn
	if addr.IsUDP() {
		udpConn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return nil, nil, nil, err
		}
		laddr.SetNetwork("udp")
		laddr.Port = uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)
		pc = &serverPacketConn{
			conn:    c,
			UDPConn: udpConn,
		}
	}
	err = WriteResponse(c, laddr, buf)
	if err != nil {
		return nil, nil, nil, err
	}
	if pc != nil {
		return nil, pc, addr, nil
	} else {
		return c, nil, addr, nil
	}
}

type serverPacketConn struct {
	remoteAddr *net.UDPAddr
	conn       net.Conn
	*net.UDPConn
}

func (pc *serverPacketConn) Close() error {
	pc.conn.Close()
	return pc.UDPConn.Close()
}

func (pc *serverPacketConn) Read(b []byte) (int, *common.NetAddr, error) {
	buf := b
	var n int
	for {
		pc.UDPConn.SetReadDeadline(time.Now().Add(time.Minute * 10))
		readN, addr, err := pc.UDPConn.ReadFromUDP(buf)
		if err != nil {
			return 0, nil, err
		}
		if pc.remoteAddr == nil {
			pc.remoteAddr = addr
		}
		if addr.AddrPort() == pc.remoteAddr.AddrPort() {
			n = readN
			break
		}
	}
	p, err := ParseUDPPacket(buf[:n])
	if err != nil {
		return 0, nil, err
	}
	n = copy(b, p.Data)
	p.Data = nil
	return n, p.NetAddr, nil
}

func (pc *serverPacketConn) Write(b []byte, addr *common.NetAddr) (n int, err error) {
	if pc.remoteAddr == nil {
		return 0, nil
	}
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
	_, err = pc.UDPConn.WriteTo(buf, pc.remoteAddr)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (pc *serverPacketConn) RemoteAddr() net.Addr {
	return pc.remoteAddr
}

package lite

import (
	"context"
	"lite/common"
	"lite/lite/http/websocket"
	"lite/lite/tcp"
	"lite/tls"
	"net"
	"sync"
)

var (
	_ TransportDialer = (*tcp.Dialer)(nil)
	_ TransportDialer = (*websocket.Dialer)(nil)

	_ net.Conn       = (*dialerConn)(nil)
	_ net.PacketConn = (*dialerPacketConn)(nil)
)

type TransportDialer interface {
	Dial(ctx context.Context, addr *common.NetAddr) (net.Conn, error)
	SetDialTCPFunc(func(ctx context.Context, addr *common.NetAddr) (net.Conn, error))
}

type Dialer struct {
	enableMeta bool
	user       *User
	serverAddr *common.NetAddr
	dialer     TransportDialer

	transport string
}

func NewDialer(serverAddr *common.NetAddr, config DialerConfig) (*Dialer, error) {
	user, err := config.User.ToUser()
	if err != nil {
		return nil, err
	}
	return &Dialer{
		user:       user,
		serverAddr: serverAddr,
	}, nil
}

func (d *Dialer) SetDialTCPFunc(fn func(ctx context.Context, addr *common.NetAddr) (net.Conn, error)) {
	d.dialer.SetDialTCPFunc(fn)
}

func (d *Dialer) SetTCPTransport(tlsConfig *tls.Config) error {
	var layer *tls.Layer
	if tlsConfig != nil {
		var err error
		layer, err = tlsConfig.ToLayer()
		if err != nil {
			return err
		}
	}
	d.dialer = tcp.NewDialer(layer)
	d.transport = "tcp"
	return nil
}

func (d *Dialer) SetWebsocketTransport(tlsConfig *tls.Config, layerConfig websocket.LayerConfig) error {
	var layer *tls.Layer
	if tlsConfig != nil {
		var err error
		layer, err = tlsConfig.ToLayer()
		if err != nil {
			return err
		}
	}
	d.dialer = websocket.NewDialer(layer, layerConfig)
	d.transport = "websocket"
	return nil
}

func (d *Dialer) User() *User {
	return d.user
}

func (d *Dialer) EnableMeta() {
	d.enableMeta = true
}

func (d *Dialer) Protocol() string {
	return Protocol
}

func (d *Dialer) Transport() string {
	return d.transport
}

func (d *Dialer) DialTCP(ctx context.Context, addr *common.NetAddr) (net.Conn, error) {
	rawConn, err := d.dialer.Dial(ctx, d.serverAddr)
	if err != nil {
		return nil, err
	}
	return &dialerConn{
		Conn:   rawConn,
		dialer: d,
		addr:   addr,
	}, nil
}

func (d *Dialer) DialUDP(ctx context.Context, addr *common.NetAddr) (net.PacketConn, error) {
	rawConn, err := d.dialer.Dial(ctx, d.serverAddr)
	if err != nil {
		return nil, err
	}
	return &dialerPacketConn{
		Conn:   rawConn,
		dialer: d,
	}, nil
}

type dialerConn struct {
	net.Conn
	dialer     *Dialer
	addr       *common.NetAddr
	reqWritten bool
	mu         sync.Mutex
}

func (c *dialerConn) writeRequest(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reqWritten {
		return 0, nil
	}
	var err error
	b := make([]byte, 0, MaxRequestPayloadSize)
	// Lite Request
	b = append(b, c.dialer.user.ID[:]...)
	b = append(b, CommandTCP)
	b, err = AppendAddr(b, c.addr)
	if err != nil {
		return 0, err
	}
	b = append(b, p...)
	_, err = c.Conn.Write(b)
	c.reqWritten = true
	c.addr = nil
	if err == nil && c.dialer.enableMeta {
		c.Conn = c.dialer.user.Wrap(c.Conn)
		c.dialer.user.AddWriteBytes(int64(len(p)))
	}
	return len(p), err
}

func (c *dialerConn) Read(b []byte) (int, error) {
	if !c.reqWritten {
		_, err := c.writeRequest(nil)
		if err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(b)
}

func (c *dialerConn) Write(b []byte) (int, error) {
	bn := len(b)
	if !c.reqWritten {
		n, err := c.writeRequest(b)
		if err != nil {
			return 0, err
		}
		b = b[n:]
	}
	if len(b) > 0 {
		_, err := c.Conn.Write(b)
		if err != nil {
			return 0, err
		}
	}
	return bn, nil
}

type dialerPacketConn struct {
	net.Conn
	dialer     *Dialer
	reqWritten bool
	mu         sync.Mutex
}

func (pc *dialerPacketConn) getRequestBytes() []byte {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.reqWritten {
		return nil
	} else {
		b := append(pc.dialer.user.ID[:], CommandUDP)
		pc.reqWritten = true
		if pc.dialer.enableMeta {
			pc.Conn = pc.dialer.user.Wrap(pc.Conn).SetDisableCount(true)
		}
		return b
	}
}

func (pc *dialerPacketConn) addRWBytes(rw bool, n int) {
	uc, ok := pc.Conn.(*UserConn)
	if ok {
		if rw {
			uc.User.AddReadBytes(int64(n))
		} else {
			uc.User.AddWriteBytes(int64(n))
		}
	}
}

func (pc *dialerPacketConn) ReadFrom(b []byte) (n int, a net.Addr, err error) {
	if !pc.reqWritten {
		reqBs := pc.getRequestBytes()
		if len(reqBs) > 0 {
			_, err := pc.Conn.Write(reqBs)
			if err != nil {
				return 0, nil, err
			}
		}
	}
	n, a, err = ReadUDPPacket(pc.Conn, b)
	if err == nil {
		pc.addRWBytes(true, n)
	}
	return
}

func (pc *dialerPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	var reqBs []byte
	if !pc.reqWritten {
		reqBs = pc.getRequestBytes()
	}
	n, err = WriteUDPPacket(pc.Conn, addr, b, reqBs)
	if err == nil {
		pc.addRWBytes(false, n)
	}
	return
}

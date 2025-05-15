package tcp

import (
	"context"
	"lite/common"
	"lite/tls"
	"net"
	"time"
)

type Dialer struct {
	tlsLayer *tls.Layer
	DialTCP  func(ctx context.Context, addr *common.NetAddr) (net.Conn, error)
}

func NewDialer(tlsLayer *tls.Layer) *Dialer {
	d := &Dialer{
		tlsLayer: tlsLayer,
	}
	return d
}

func (d *Dialer) Dial(ctx context.Context, addr *common.NetAddr) (net.Conn, error) {
	var (
		c   net.Conn
		err error
	)
	if d.DialTCP == nil {
		c, err = Dial(ctx, addr.Address())
	} else {
		c, err = d.DialTCP(ctx, addr)
	}
	if err != nil {
		return nil, err
	}
	if d.tlsLayer != nil {
		c = d.tlsLayer.Client(c)
	}
	return c, nil
}

func (d *Dialer) SetDialTCPFunc(fn func(ctx context.Context, addr *common.NetAddr) (net.Conn, error)) {
	d.DialTCP = fn
}

func (d *Dialer) Close() error { return nil }

func Dial(ctx context.Context, addr string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout: 10 * time.Second,
	}
	return d.DialContext(ctx, "tcp", addr)
}

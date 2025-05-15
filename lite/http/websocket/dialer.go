package websocket

import (
	"context"
	"lite/common"
	"lite/lite/tcp"
	"lite/tls"
	"net"
)

type Dialer struct {
	tlsLayer *tls.Layer
	wsLayer  *Layer
	DialTCP  func(ctx context.Context, addr *common.NetAddr) (net.Conn, error)
}

func NewDialer(tlsLayer *tls.Layer, layerConfig LayerConfig) *Dialer {
	if tlsLayer != nil {
		tlsLayer.NextProtos = []string{"http/1.1"}
	}
	return &Dialer{
		tlsLayer: tlsLayer,
		wsLayer:  NewLayer(layerConfig),
	}
}

func (d *Dialer) SetDialTCPFunc(fn func(ctx context.Context, addr *common.NetAddr) (net.Conn, error)) {
	d.DialTCP = fn
}

func (d *Dialer) Dial(ctx context.Context, addr *common.NetAddr) (net.Conn, error) {
	var (
		c   net.Conn
		err error
	)
	if d.DialTCP == nil {
		c, err = tcp.Dial(ctx, addr.Address())
	} else {
		c, err = d.DialTCP(ctx, addr)
	}
	if err != nil {
		return nil, err
	}
	if d.tlsLayer != nil {
		c = d.tlsLayer.Client(c)
	}
	c = d.wsLayer.Client(c)
	return c, nil
}

func (d *Dialer) Close() error { return nil }

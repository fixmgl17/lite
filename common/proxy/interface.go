package proxy

import (
	"context"
	"io"
	"lite/common"
	"net"
	"time"
)

type Processor interface {
	HandleError(c net.Conn, err error)
	HandleConn(ctx context.Context, c net.Conn, addr *common.NetAddr)
	HandlePacketConn(ctx context.Context, pc PacketConn)
}

type PacketConn interface {
	io.Closer
	Read(b []byte) (int, *common.NetAddr, error)
	Write(b []byte, src *common.NetAddr) (int, error)
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

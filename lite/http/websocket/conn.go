package websocket

import (
	"bytes"
	"io"
	"net"
	"time"

	"github.com/gorilla/websocket"
)

var (
	_ net.Conn = (*wsConn)(nil)
)

type wsConn struct {
	*websocket.Conn
	r io.Reader
}

func newWsConn(conn *websocket.Conn, rBuf []byte) *wsConn {
	c := &wsConn{Conn: conn}
	if len(rBuf) > 0 {
		c.r = bytes.NewReader(rBuf)
	}
	return c
}

func (c *wsConn) Close() error {
	defer c.Conn.Close()
	return c.Conn.CloseHandler()(websocket.CloseNormalClosure, "")
}

func (c *wsConn) Read(b []byte) (int, error) {
	if c.r == nil {
		if _, r, err := c.Conn.NextReader(); err == nil {
			c.r = r
		} else {
			if _, ok := err.(*websocket.CloseError); ok {
				return 0, io.EOF
			}
			return 0, err
		}
	}
	n, err := c.r.Read(b)
	if err == io.EOF {
		c.r = nil
		err = nil
	}
	return n, err
}

func (c *wsConn) Write(b []byte) (int, error) {
	err := c.Conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *wsConn) SetDeadline(t time.Time) error {
	if err := c.Conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.Conn.SetWriteDeadline(t)
}

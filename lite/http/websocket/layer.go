package websocket

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type LayerConfig struct {
	Headers             map[string]string `json:"headers"`
	Path                string            `json:"path"`
	Host                string            `json:"host"`
	EarlyDataHeaderName string            `json:"early_data_header_name"`
	OnlyHTTPUpgrade     bool              `json:"only_http_upgrade"`
}

type Layer struct {
	config LayerConfig
	header http.Header
}

func NewLayer(config LayerConfig) *Layer {
	layer := &Layer{
		config: config,
		header: http.Header{},
	}
	for k, v := range config.Headers {
		layer.header.Set(k, v)
	}
	delete(layer.header, "Sec-Websocket-Protocol")
	return layer
}

func (l *Layer) Client(c net.Conn) net.Conn {
	if l.config.OnlyHTTPUpgrade {
		return l.httpUpgradeClient(c)
	}
	wd := &websocket.Dialer{
		HandshakeTimeout:  time.Second * 8,
		EnableCompression: true,
		NetDialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return c, nil
		},
	}
	return &wsClientConn{
		Conn:   c,
		layer:  l,
		dialer: wd,
	}
}

var (
	_ net.Conn = (*wsClientConn)(nil)
)

type wsClientConn struct {
	net.Conn
	layer  *Layer
	dialer *websocket.Dialer
	mu     sync.Mutex
}

func (c *wsClientConn) handshake(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dialer == nil {
		return 0, nil
	}
	header := c.layer.header.Clone()
	if header == nil {
		header = make(http.Header)
	}
	if len(p) > 0 {
		header[c.layer.config.EarlyDataHeaderName] = []string{base64.RawURLEncoding.EncodeToString(p)}
	}
	wsConn, _, err := c.dialer.Dial("ws://"+c.layer.config.Host+c.layer.config.Path, header)
	if err != nil {
		return 0, err
	}
	c.Conn = newWsConn(wsConn, nil)
	c.dialer = nil
	c.layer = nil
	return len(p), nil
}

func (c *wsClientConn) Read(b []byte) (int, error) {
	if c.dialer != nil {
		_, err := c.handshake(nil)
		if err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(b)
}

func (c *wsClientConn) Write(b []byte) (int, error) {
	bn := len(b)
	if c.dialer != nil {
		var p []byte
		if c.layer.config.EarlyDataHeaderName != "" {
			p = b
			if len(b) > MaxEarlyDataSize {
				p = p[:MaxEarlyDataSize]
			}
		}
		n, err := c.handshake(p)
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

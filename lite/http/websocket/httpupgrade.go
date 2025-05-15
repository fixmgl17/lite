package websocket

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"lite/common"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"math/rand/v2"
)

var subProtocols = []string{"wamp", "soap", "mqtt"}

func randomSubProtocol() string {
	return subProtocols[rand.IntN(len(subProtocols))]
}

func getSubProtocol(r *http.Request) string {
	return strings.TrimSpace(strings.Split(r.Header["Sec-Websocket-Protocol"][0], ",")[0])
}

func (p *Processor) handleHTTPUpgrade(w http.ResponseWriter, r *http.Request) {
	if !IsWebsocketUpgradeRequest(r) {
		common.SendFakeNginxResponse(w, http.StatusUpgradeRequired, "")
		p.handleConn(nil, common.NewErrorWithRequest(r, "invalid upgrade request"))
		return
	}
	protocol := getSubProtocol(r)
	if !slices.Contains(subProtocols, protocol) {
		common.SendFakeNginxResponse(w, http.StatusUpgradeRequired, "")
		p.handleConn(nil, common.NewErrorWithRequest(r, "invalid sub-protocol "+protocol))
		return
	}
	h, ok := w.(http.Hijacker)
	if !ok {
		common.SendFakeNginxResponse(w, http.StatusNotImplemented, "")
		p.handleConn(nil, common.NewErrorWithRequest(r, "failed to assert http.Hijacker"))
		return
	}
	c, rw, err := h.Hijack()
	if err != nil {
		common.SendFakeNginxResponse(w, http.StatusInternalServerError, "")
		p.handleConn(nil, common.NewErrorWithRequest(r, "failed to hijack connection: "+err.Error()))
		return
	}
	cacheConn := common.NewCacheConn(c).AddCacheFromReader(rw.Reader)
	resp := &http.Response{
		Status:     "101 Switching Protocols",
		StatusCode: 101,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	resp.Header["Connection"] = []string{"Upgrade"}
	resp.Header["Upgrade"] = []string{"websocket"}
	resp.Header["Sec-Websocket-Protocol"] = []string{protocol}
	resp.Header["Sec-Websocket-Accept"] =
		[]string{ComputeWebSocketAccept(r.Header["Sec-Websocket-Key"][0])}
	resp.Header["Date"] = []string{time.Now().UTC().Format(http.TimeFormat)}
	resp.Header["Server"] = []string{"nginx"}
	b, err := httputil.DumpResponse(resp, false)
	if err != nil {
		// should not happen
		panic(err)
	}
	_, err = cacheConn.Write(b)
	if err != nil {
		c.Close()
		p.handleConn(nil, common.NewErrorWithRequest(r, err.Error()))
		return
	}
	if p.config.EarlyDataHeaderName != "" {
		if data := r.Header.Get(p.config.EarlyDataHeaderName); data != "" {
			b, err := base64.RawURLEncoding.DecodeString(data)
			if err == nil {
				cacheConn.AddCache(b)
			}
		}
	}
	p.handleConn(cacheConn.Unwrap(), nil)
}

func (l *Layer) httpUpgradeClient(c net.Conn) net.Conn {
	path, rawQuery, found := strings.Cut(l.config.Path, "?")
	if found {
		rawQuery = "?" + rawQuery
	}
	req := &http.Request{
		Method: http.MethodGet,
		URL: &url.URL{
			Scheme:   "http",
			Host:     l.config.Host,
			Path:     path,
			RawQuery: rawQuery,
		},
		Host: l.config.Host,
	}
	req.Header = l.header.Clone()
	req.Header["Sec-Websocket-Version"] = []string{"13"}
	req.Header["Sec-Websocket-Extensions"] = []string{"permessage-deflate"}
	req.Header["Sec-Websocket-Key"] = []string{GenerateWebSocketKey()}
	req.Header["Sec-Websocket-Protocol"] = []string{randomSubProtocol()}
	req.Header["Connection"] = []string{"Upgrade"}
	req.Header["Upgrade"] = []string{"websocket"}
	return &upgradeConn{
		Conn:  c,
		layer: l,
		req:   req,
	}
}

type upgradeConn struct {
	net.Conn
	layer      *Layer
	mu         sync.Mutex
	req        *http.Request
	reqWritten bool
	r          io.Reader
}

func (c *upgradeConn) writeRequest(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reqWritten {
		return 0, nil
	}
	if len(p) > 0 {
		c.req.Header[c.layer.config.EarlyDataHeaderName] = []string{base64.RawURLEncoding.EncodeToString(p)}
	}
	err := c.req.Write(c.Conn)
	c.reqWritten = true
	if err == nil {
		return len(p), nil
	} else {
		return 0, err
	}
}

func (c *upgradeConn) readResponse() error {
	r, isBufferedConn := common.NewReaderSizeFromConn(c.Conn, 0)
	c.SetReadDeadline(time.Now().Add(8 * time.Second))
	resp, err := http.ReadResponse(r, c.req)
	if isBufferedConn {
		c.r = c.Conn
	} else {
		c.r = r
	}
	if err != nil {
		return err
	}
	c.SetReadDeadline(time.Time{})
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("unexpected status %s when upgrading http", resp.Status)
	}
	if len(resp.Header["Sec-Websocket-Accept"]) == 0 || resp.Header["Sec-Websocket-Accept"][0] != ComputeWebSocketAccept(resp.Request.Header["Sec-Websocket-Key"][0]) {
		return errors.New("invalid Sec-Websocket-Accept")
	}
	if c.req.Header["Sec-Websocket-Protocol"][0] != resp.Header["Sec-Websocket-Protocol"][0] {
		return errors.New("invalid Sec-Websocket-Protocol")
	}
	c.req = nil
	return nil
}

func (c *upgradeConn) Read(b []byte) (int, error) {
	if !c.reqWritten {
		_, err := c.writeRequest(nil)
		if err != nil {
			return 0, err
		}
	}
	if c.r == nil {
		err := c.readResponse()
		if err != nil {
			return 0, err
		}
	}
	return c.r.Read(b)
}

func (c *upgradeConn) Write(b []byte) (int, error) {
	bn := len(b)
	if c.req != nil {
		var p []byte
		if c.layer.config.EarlyDataHeaderName != "" {
			p = b
			if len(b) > MaxEarlyDataSize {
				p = p[:MaxEarlyDataSize]
			}
		}
		n, err := c.writeRequest(p)
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

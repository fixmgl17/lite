package websocket

import (
	"context"
	"encoding/base64"
	"fmt"
	"lite/common"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

type ProcessorConfig struct {
	Path                string `json:"path"`
	Host                string `json:"host"`
	EarlyDataHeaderName string `json:"early_data_header_name"`
	Fallback            string `json:"fallback"`
}

type Processor struct {
	config          ProcessorConfig
	fallbackHandler http.Handler
	upgrader        *websocket.Upgrader
	HandleConn      func(net.Conn, error)
}

func NewHTTPProcessor(config ProcessorConfig) (*Processor, error) {
	p := &Processor{
		config: config,
	}
	if config.Fallback != "" {
		fb, err := common.NewReverseProxyOrFileHandler(config.Fallback)
		if err != nil {
			return nil, err
		}
		p.fallbackHandler = fb
	}
	p.upgrader = &websocket.Upgrader{
		HandshakeTimeout:  time.Second * 8,
		CheckOrigin:       func(r *http.Request) bool { return true },
		EnableCompression: false,
		Error: func(w http.ResponseWriter, r *http.Request, status int, reason error) {
			common.SendFakeNginxResponse(w, status, "")
			p.handleConn(nil, common.NewErrorWithRequest(r, reason.Error()))
		},
	}
	return p, nil
}

func (p *Processor) CheckPath(path string) error {
	if p.config.Path != "" && p.config.Path != path {
		return fmt.Errorf("invalid path: %s", path)
	}
	return nil
}

func (p *Processor) CheckHost(host string) error {
	if p.config.Host != "" && p.config.Host != host {
		return fmt.Errorf("invalid host: %s", host)
	}
	return nil
}

func (p *Processor) handleConn(c net.Conn, err error) {
	if p.HandleConn != nil {
		p.HandleConn(c, err)
	} else if c != nil {
		c.Close()
	}
}

func (p *Processor) HandleHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor != 1 {
		if p.fallbackHandler != nil {
			p.fallbackHandler.ServeHTTP(w, r)
		} else {
			common.SendFakeNginxResponse(w, http.StatusHTTPVersionNotSupported, "")
		}
		p.handleConn(nil, common.NewErrorWithRequest(r, "must be HTTP/1.1"))
		return
	}
	err := p.CheckHost(r.Host)
	if err != nil {
		if p.fallbackHandler != nil {
			p.fallbackHandler.ServeHTTP(w, r)
		} else {
			common.SendFakeNginxResponse(w, http.StatusForbidden, "")
		}
		p.handleConn(nil, common.NewErrorWithRequest(r, err.Error()))
		return
	}
	err = p.CheckPath(r.URL.Path)
	if err != nil {
		if p.fallbackHandler != nil {
			p.fallbackHandler.ServeHTTP(w, r)
		} else {
			common.SendFakeNginxResponse(w, http.StatusNotFound, "")
		}
		p.handleConn(nil, common.NewErrorWithRequest(r, err.Error()))
		return
	}
	if len(r.Header["Sec-Websocket-Protocol"]) > 0 {
		p.handleHTTPUpgrade(w, r)
		return
	}
	header := http.Header{
		"Server": []string{"nginx"},
		"Date":   []string{time.Now().Format(http.TimeFormat)},
	}
	wsC, err := p.upgrader.Upgrade(w, r, header)
	if err != nil {
		return
	}
	var rBuf []byte
	if p.config.EarlyDataHeaderName != "" {
		if data := r.Header.Get(p.config.EarlyDataHeaderName); data != "" {
			b, err := base64.RawURLEncoding.DecodeString(data)
			if err == nil {
				rBuf = b
			}
		}
	}
	p.handleConn(newWsConn(wsC, rBuf), nil)
}

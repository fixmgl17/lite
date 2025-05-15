package http

import (
	"context"
	"crypto/tls"
	"errors"
	"lite/common"
	"lite/lite/http/websocket"
	"net"
	"net/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type Server struct {
	tlsConfig *tls.Config
	processor *websocket.Processor
	server    *http.Server
}

func NewServer(tlsConfig *tls.Config, processor *websocket.Processor) *Server {
	srv := &Server{processor: processor}
	if tlsConfig != nil {
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
		srv.tlsConfig = tlsConfig
	}
	srv.processor = processor
	return srv
}

// http/1.1 & http2
func (srv *Server) ListenAndServe(ctx context.Context, addr string, handler func(ctx context.Context, c net.Conn, err error)) error {
	srv.processor.HandleConn = func(c net.Conn, err error) {
		handler(ctx, c, err)
	}
	srv.server = &http.Server{
		DisableGeneralOptionsHandler: true,
		// ErrorLog:                     log.New(io.Discard, "", 0),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			srv.processor.HandleHTTP(ctx, w, r)
		}),
	}
	listenConfig := &net.ListenConfig{}
	listener, err := listenConfig.Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	if srv.tlsConfig == nil {
		// h2c && h1
		srv.server.Handler = h2c.NewHandler(srv.server.Handler, &http2.Server{})
	} else {
		listener = tls.NewListener(listener, srv.tlsConfig)
	}
	err = srv.server.Serve(listener)
	if err != nil && errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (srv *Server) Close() error {
	return common.TryToClose(srv.server)
}

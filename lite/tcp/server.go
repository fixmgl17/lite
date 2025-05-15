package tcp

import (
	"context"
	"crypto/tls"
	"errors"
	"lite/common"
	"net"
)

type Server struct {
	tlsConfig *tls.Config
	listener  net.Listener
}

func NewServer(tlsConfig *tls.Config) *Server {
	return &Server{
		tlsConfig: tlsConfig,
	}
}

func (srv *Server) Close() (err error) {
	return common.TryToClose(srv.listener)
}

func (srv *Server) ListenAndServe(ctx context.Context, addr string, handler func(ctx context.Context, c net.Conn, err error)) error {
	listenConfig := &net.ListenConfig{}
	listener, err := listenConfig.Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	srv.listener = listener
	for {
		c, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			} else {
				srv.Close()
				return err
			}
		}
		c = common.NewBufferedConnSize(c, 4*1024)
		if srv.tlsConfig != nil {
			c = tls.Server(c, srv.tlsConfig)
		}
		go func() {
			handler(ctx, c, nil)
			// ensure the connection is closed
			c.Close()
		}()
	}
}

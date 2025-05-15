package mixed

import (
	"context"
	"fmt"
	"lite/common"
	"lite/common/proxy"
	"lite/lite/tcp"
	"lite/mixed/http"
	"lite/mixed/socks5"
	"net"
)

const Protocol = "mixed"

type Server struct {
	config ServerConfig
	server *tcp.Server
}

func NewServer(config ServerConfig) *Server {
	return &Server{
		server: tcp.NewServer(nil),
		config: config,
	}
}

func (s *Server) Protocol() string {
	return Protocol
}

func (s *Server) User() (username, password string) {
	return s.config.Username, s.config.Password
}

func (s *Server) ListenAndServe(ctx context.Context, addr string, processor proxy.Processor) error {
	return s.server.ListenAndServe(ctx, addr, func(ctx context.Context, c net.Conn, err error) {
		if err != nil {
			processor.HandleError(c, fmt.Errorf("mixed server listen and serve: %v", err))
			return
		}
		r, isBufferedConn := common.NewReaderSizeFromConn(c, 0)
		b, err := r.Peek(1)
		if err != nil {
			processor.HandleError(c, fmt.Errorf("mixed server peek: %v", err))
			return
		}
		if !isBufferedConn {
			c = common.NewCacheConn(c).AddCacheFromReader(r).Unwrap()
		}
		if b[0] == socks5.Version {
			c2, pc, addr, err := socks5.ServeProxy(c, s.config.Username, s.config.Password)
			if err != nil {
				processor.HandleError(c, fmt.Errorf("mixed server serve socks5 proxy: %v", err))
			} else if pc != nil {
				processor.HandlePacketConn(ctx, pc)
			} else {
				processor.HandleConn(ctx, c2, addr)
			}
		} else {
			c2, addr, err := http.ServeProxy(c, s.config.Username, s.config.Password)
			if err != nil {
				processor.HandleError(c, fmt.Errorf("mixed server serve http proxy: %v", err))
				return
			} else {
				processor.HandleConn(ctx, c2, addr)
			}
		}
	})
}

func (s *Server) Close() error {
	return common.TryToClose(s.server)
}

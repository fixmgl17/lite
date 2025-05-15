package lite

import (
	"context"
	gotls "crypto/tls"
	"fmt"
	"io"
	"lite/common"
	"lite/common/proxy"
	"lite/lite/http"
	"lite/lite/http/websocket"
	"lite/lite/tcp"
	"lite/tls"
	"net"
	"sync"
)

type TransportServer interface {
	io.Closer
	ListenAndServe(ctx context.Context, addr string, handler func(ctx context.Context, c net.Conn, err error)) error
}

var (
	_ TransportServer = (*tcp.Server)(nil)
	_ TransportServer = (*http.Server)(nil)

	_ proxy.PacketConn = (*serverPacketConn)(nil)
)

type Server struct {
	enableMeta bool
	userMap    sync.Map
	server     TransportServer

	transport string
}

func NewServer(config ServerConfig) (*Server, error) {
	srv := &Server{}
	for i, v := range config.Users {
		err := srv.AddUser(v)
		if err != nil {
			return nil, fmt.Errorf("%dth user: %v", i+1, err)
		}
	}
	return srv, nil
}

func (s *Server) SetTCPTransport(tlsConfig *tls.Config) error {
	var conf *gotls.Config
	if tlsConfig != nil {
		var err error
		conf, err = tlsConfig.ToServerTLSConfig()
		if err != nil {
			return err
		}
	}
	s.server = tcp.NewServer(conf)
	s.transport = "tcp"
	if tlsConfig != nil {
		s.transport = "tls+" + s.transport
	}
	return nil
}

func (s *Server) SetWebsocketTransport(tlsConfig *tls.Config, processorConfig websocket.ProcessorConfig) error {
	var conf *gotls.Config
	if tlsConfig != nil {
		var err error
		conf, err = tlsConfig.ToServerTLSConfig()
		if err != nil {
			return err
		}
	}
	processor, err := websocket.NewHTTPProcessor(processorConfig)
	if err != nil {
		return err
	}
	s.server = http.NewServer(conf, processor)
	s.transport = "websocket"
	if tlsConfig != nil {
		s.transport = "tls+" + s.transport
	}
	return nil
}

func (s *Server) Protocol() string {
	return Protocol
}

func (s *Server) Transport() string {
	return s.transport
}

func (s *Server) EnableMeta() {
	s.enableMeta = true
}

func (s *Server) GetUser(id string) *User {
	v, ok := s.userMap.Load(id)
	if !ok {
		return nil
	}
	return v.(*User)
}

func (s *Server) AddUser(userConf UserConfig) error {
	user, err := userConf.ToUser()
	if err != nil {
		return err
	}
	old, loaded := s.userMap.LoadOrStore(user.ID, user)
	if loaded {
		old.(*User).ForceExpire()
	}
	return nil
}

func (s *Server) RemoveUser(idStr string) error {
	id, err := ParseStringID(idStr)
	if err != nil {
		return err
	}
	v, loaded := s.userMap.LoadAndDelete(id)
	if loaded {
		v.(*User).ForceExpire()
	}
	return nil
}

func (s *Server) RangeUser(f func(user *User) bool) {
	s.userMap.Range(func(_, value any) bool {
		return f(value.(*User))
	})
}

func (s *Server) readRequest(r io.Reader) (*common.NetAddr, *User, error) {
	buf := common.GetBuffer(256)
	defer common.PutBuffer(buf)
	_, err := io.ReadFull(r, buf[:16])
	if err != nil {
		return nil, nil, err
	}
	user := s.GetUser(string(buf[:16]))
	if user == nil {
		return nil, nil, fmt.Errorf("not found uuid %02X", buf[:16])
	}
	_, err = io.ReadFull(r, buf[:1])
	if err != nil {
		return nil, nil, err
	}
	var a *common.NetAddr
	switch buf[0] {
	case CommandTCP:
		a, err = ReadAddr(r, buf)
		if err != nil {
			return nil, nil, err
		}
		a.SetNetwork("tcp")
	case CommandUDP:
	default:
		return nil, nil, fmt.Errorf("unknown command %d", buf[0])
	}
	return a, user, nil
}

func (s *Server) ListenAndServe(ctx context.Context, addr string, processor proxy.Processor) error {
	if s.server == nil {
		return fmt.Errorf("transport server is nil")
	}
	return s.server.ListenAndServe(ctx, addr, func(ctx context.Context, c net.Conn, err error) {
		if err != nil {
			processor.HandleError(c, fmt.Errorf("lite server listen and serve: %v", err))
			return
		}
		a, user, err := s.readRequest(c)
		if err != nil {
			processor.HandleError(c, fmt.Errorf("lite server read request: %v", err))
			return
		}
		if a != nil {
			if s.enableMeta {
				c = user.Wrap(c)
			}
			processor.HandleConn(ctx, c, a)
		} else {
			if s.enableMeta {
				c = user.Wrap(c).SetDisableCount(true)
			}
			processor.HandlePacketConn(ctx, &serverPacketConn{
				Conn: c,
			})
		}
	})
}

func (s *Server) Close() error {
	return common.TryToClose(s.server)
}

type serverPacketConn struct {
	net.Conn
}

func (pc *serverPacketConn) addRWBytes(rw bool, n int) {
	uc, ok := pc.Conn.(*UserConn)
	if ok {
		if rw {
			uc.User.AddReadBytes(int64(n))
		} else {
			uc.User.AddWriteBytes(int64(n))
		}
	}
}

func (pc *serverPacketConn) Read(b []byte) (n int, a *common.NetAddr, err error) {
	n, a, err = ReadUDPPacket(pc.Conn, b)
	if err == nil {
		pc.addRWBytes(true, n)
	}
	return
}

func (pc *serverPacketConn) Write(b []byte, src *common.NetAddr) (n int, err error) {
	n, err = WriteUDPPacket(pc.Conn, src, b, nil)
	if err == nil {
		pc.addRWBytes(false, n)
	}
	return
}

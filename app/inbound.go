package app

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"lite/common"
	"lite/common/proxy"
	"lite/lite"
	"lite/lite/http/websocket"
	"lite/mixed"
	"net"
	"net/netip"
	"sync"
)

var _ proxy.Processor = (*Inbound)(nil)

type Inbound struct {
	Tag string

	ListenAddr *common.NetAddr

	mixedServer *mixed.Server

	liteServer *lite.Server

	GetOutbound func(addr *common.NetAddr) *Outbound

	connStore sync.Map
}

func (inb *Inbound) Info() (protocol string, transport string) {
	if inb.liteServer != nil {
		return inb.liteServer.Protocol(), inb.liteServer.Transport()
	}
	return inb.mixedServer.Protocol(), ""
}

func (inb *Inbound) HandlePacketConn(ctx context.Context, pc proxy.PacketConn) {
	id := genUniqueConnID()
	inb.connStore.Store(id, pc)
	defer inb.connStore.Delete(id)
	defer pc.Close()
	logger.Debug("[", inb.Tag, "]", " handle packet conn from ", pc.RemoteAddr())
	var (
		targetPc net.PacketConn
		ob       *Outbound
		once     sync.Once
		fatalErr error
		ch       = make(chan struct{}, 1)
		nl       sync.RWMutex
		nat      = make(map[string]*netip.Addr)
	)
	go func() {
		buf := common.GetBuffer(64 * 1024)
		defer common.PutBuffer(buf)
		var finalErr error
		for {
			n, addr, err := pc.Read(buf)
			if err != nil {
				finalErr = err
				break
			}
			if targetPc == nil {
				a := addr.Clone()
				ob = inb.GetOutbound(a)
				logger.Info("[", inb.Tag, " -> ", ob.Tag, "] build udp transport ", pc.RemoteAddr(), " => ", addr.Network(), "://", addr.String())
				_ = resolveIPWithMode(ctx, ob.Resolver, ob.DNSResolve, a)
				targetPc, err = ob.DialUDP(ctx, a)
				if err != nil {
					if err != ErrBlockOutbound {
						once.Do(func() {
							fatalErr = err
							ch <- struct{}{}
						})
						return
					}
					continue
				} else {
					go func() {
						buf := common.GetBuffer(64 * 1024)
						defer common.PutBuffer(buf)
						var finalErr error
						for {
							n, addr, err := targetPc.ReadFrom(buf)
							if err != nil {
								finalErr = err
								break
							}
							naddr, err := common.ConvertAddr(addr)
							if err != nil {
								finalErr = err
								break
							}
							if ob.DNSResolve != "" && naddr.IsIP() {
								nl.RLock()
								for k, v := range nat {
									if naddr.IP.Compare(*v) == 0 {
										naddr.FQDN = k
										naddr.IP = nil
										break
									}
								}
								nl.RUnlock()
							}
							logger.Debug("[", inb.Tag, "] ", pc.RemoteAddr(), " <= ", naddr.Network(), "://", naddr, " (", n, "B)")
							_, err = pc.Write(buf[:n], naddr)
							if err != nil {
								finalErr = err
								break
							}
						}
						// ignore EOF
						if finalErr == io.EOF {
							finalErr = nil
						}
						once.Do(func() {
							fatalErr = finalErr
							ch <- struct{}{}
						})
					}()
				}
			}
			logger.Debug("[", inb.Tag, "] ", pc.RemoteAddr(), " => ", addr.Network(), "://", addr, " (", n, "B)")
			if ob.DNSResolve != "" && addr.IsFQDN() {
				fqdn := addr.FQDN
				nl.RLock()
				a := nat[fqdn]
				nl.RUnlock()
				if a != nil {
					addr.FQDN = ""
					addr.IP = a
				} else {
					err := resolveIPWithMode(ctx, ob.Resolver, ob.DNSResolve, addr)
					if err == nil {
						nl.Lock()
						nat[fqdn] = addr.IP
						nl.Unlock()
					}
				}
			}
			_, err = targetPc.WriteTo(buf[:n], addr)
			if err != nil {
				finalErr = err
				break
			}
		}
		// ignore EOF
		if finalErr == io.EOF {
			finalErr = nil
		}
		once.Do(func() {
			fatalErr = finalErr
			ch <- struct{}{}
		})
	}()
	<-ch
	if targetPc != nil {
		targetPc.Close()
	}
	if fatalErr != nil {
		logger.Error("[", inb.Tag, "] connection ", pc.LocalAddr(), " <=> ", pc.RemoteAddr(), " closed: ", fatalErr)
	} else {
		logger.Debug("[", inb.Tag, "] connection ", pc.LocalAddr(), " <=> ", pc.RemoteAddr(), " closed")
	}
}

func (inb *Inbound) HandleConn(ctx context.Context, c net.Conn, addr *common.NetAddr) {
	id := genUniqueConnID()
	inb.connStore.Store(id, c)
	defer inb.connStore.Delete(id)
	defer c.Close()
	ob := inb.GetOutbound(addr)
	logger.Info("[", inb.Tag, " -> ", ob.Tag, "] ", "build tcp transport ", c.RemoteAddr(), " => ", addr.Network(), "://", addr)
	var actualAddr = addr.Clone()
	_ = resolveIPWithMode(ctx, ob.Resolver, ob.DNSResolve, actualAddr)
	targetConn, err := ob.DialTCP(ctx, actualAddr)
	if err != nil {
		logger.Error("[", inb.Tag, "] connection ", c.LocalAddr(), " <=> ", c.RemoteAddr(), " closed: ", err)
		return
	}
	defer targetConn.Close()
	logger.Debug("[", inb.Tag, "] connected stream ", c.RemoteAddr(), " <=> ", targetConn.RemoteAddr())
	err = common.ConnectStream(c, targetConn, 32*1024)
	if err != nil {
		logger.Error("[", inb.Tag, "] connection ", c.LocalAddr(), " <=> ", c.RemoteAddr(), " closed: ", err)
	} else {
		logger.Debug("[", inb.Tag, "] connection ", c.LocalAddr(), " <=> ", c.RemoteAddr(), " closed")
	}
}

func (inb *Inbound) HandleError(c net.Conn, err error) {
	if c != nil {
		c.Close()
		logger.Error("[", inb.Tag, "] connection ", c.LocalAddr(), " <=> ", c.RemoteAddr(), " closed: ", err)
	} else {
		logger.Error("[", inb.Tag, "] ", err)
	}
}

func (inb *Inbound) Start(ctx context.Context) error {
	if inb.liteServer != nil {
		return inb.liteServer.ListenAndServe(ctx, inb.ListenAddr.String(), inb)
	}
	return inb.mixedServer.ListenAndServe(ctx, inb.ListenAddr.String(), inb)
}

func (inb *Inbound) Close() (err error) {
	if inb.liteServer != nil {
		err = inb.liteServer.Close()
	} else {
		err = inb.mixedServer.Close()
	}
	inb.connStore.Range(func(_, v any) bool {
		v.(io.Closer).Close()
		return true
	})
	return err
}

func genUniqueConnID() (id [4]byte) {
	_, err := rand.Read(id[:])
	if err != nil {
		panic(err)
	}
	return
}

func BuildInbound(config *InboundConfig) (*Inbound, error) {
	switch config.Transport {
	case "":
		config.Transport = "tcp"
	case "ws":
		config.Transport = "websocket"
	}
	switch config.Protocol {
	case "http", "socks5":
		config.Protocol = "mixed"
	}
	var err error
	inb := &Inbound{Tag: config.Tag}
	inb.ListenAddr, err = parseListenAddr(config.Listen)
	if err != nil {
		return nil, err
	}
	switch config.Protocol {
	case "mixed":
		var serverConf mixed.ServerConfig
		err = common.ConvertStruct(config.ProtocolSettings, &serverConf)
		if err != nil {
			return nil, err
		}
		inb.mixedServer = mixed.NewServer(serverConf)
	case "lite":
		var serverConf lite.ServerConfig
		err = common.ConvertStruct(config.ProtocolSettings, &serverConf)
		if err != nil {
			return nil, err
		}
		server, err := lite.NewServer(serverConf)
		if err != nil {
			return nil, err
		}
		switch config.Transport {
		case "tcp":
			err = server.SetTCPTransport(config.TLS)
		case "websocket":
			var processorConfig websocket.ProcessorConfig
			err = common.ConvertStruct(config.TransportSettings, &processorConfig)
			if err != nil {
				return nil, err
			}
			err = server.SetWebsocketTransport(config.TLS, processorConfig)
		default:
			err = fmt.Errorf("invalid inbound transport for lite: %s", config.Transport)
		}
		if err != nil {
			return nil, err
		}
		inb.liteServer = server
	default:
		err = fmt.Errorf("invalid inbound protocol: %s", config.Protocol)
	}
	if err != nil {
		return nil, err
	}
	return inb, nil
}

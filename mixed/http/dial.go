package http

import (
	"lite/common"
	"net"
)

func DialTCP(c net.Conn, addr *common.NetAddr, username, password string) (net.Conn, error) {
	req := NewRequest(addr)
	if username != "" || password != "" {
		req.SetProxyBasicAuth(username, password)
	}
	err := WriteRequest(c, req)
	if err != nil {
		return nil, err
	}
	r, isBufferedConn := common.NewReaderSizeFromConn(c, 0)
	_, err = ReadResponse(r)
	if err != nil {
		return nil, err
	}
	if !isBufferedConn {
		c = common.NewCacheConn(c).AddCacheFromReader(r).Unwrap()
	}
	return c, nil
}

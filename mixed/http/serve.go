package http

import (
	"errors"
	"lite/common"
	"net"
	"net/http"
	"net/http/httputil"
)

func ServeProxy(c net.Conn, username, password string) (net.Conn, *common.NetAddr, error) {
	r, isBufferedConn := common.NewReaderSizeFromConn(c, 0)
	req, err := ReadRequest(r)
	if err != nil {
		return nil, nil, err
	}
	if username != "" || password != "" {
		reqUsername, reqPassword, ok := req.ProxyBasicAuth()
		if !ok {
			err = errors.New("no basic auth")
		} else if reqUsername != username {
			err = errors.New("auth failed: wrong username " + username)
		} else if reqPassword != password {
			err = errors.New("auth failed: wrong password " + password)
		}
		if err != nil {
			WriteResponse(c, req, false)
			return nil, nil, err
		}
	}
	err = WriteResponse(c, req, true)
	if err != nil {
		return nil, nil, err
	}
	var buf []byte
	if req.Method != http.MethodConnect {
		buf, _ = httputil.DumpRequest(RestoreRequest(req), false)
	}
	cacheConn := common.NewCacheConn(c)
	if !isBufferedConn {
		cacheConn.AddCacheFromReader(r)
	}
	if len(buf) > 0 {
		cacheConn.AddCache(buf)
	}
	return cacheConn.Unwrap(), req.NetAddr, nil
}

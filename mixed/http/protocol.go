package http

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"lite/common"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const Protocol = "http"

type Request struct {
	*http.Request
	NetAddr   *common.NetAddr
	TargetURL *url.URL
}

func (req *Request) SetProxyBasicAuth(username, password string) {
	if req.Request.Header == nil {
		req.Request.Header = make(map[string][]string)
	}
	req.Header["Proxy-Authorization"] = []string{"Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))}
}

func (req *Request) ProxyBasicAuth() (username, password string, ok bool) {
	values := req.Header["Proxy-Authorization"]
	if len(values) == 0 {
		return "", "", false
	}
	auth := values[0]
	const prefix = "Basic "
	if len(auth) < len(prefix) || auth[:len(prefix)] != prefix {
		return "", "", false
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", false
	}
	cs := string(c)
	username, password, ok = strings.Cut(cs, ":")
	if !ok {
		return "", "", false
	}
	return username, password, true
}

func ReadRequest(r *bufio.Reader) (*Request, error) {
	httpReq, err := http.ReadRequest(r)
	if err != nil {
		return nil, err
	}
	// Proxy-Connection not supported
	delete(httpReq.Header, "Proxy-Connection")
	delete(httpReq.Header, "Connection")
	req := &Request{
		Request: httpReq,
	}
	if req.Method == http.MethodConnect {
		lastIndex := strings.LastIndex(req.RequestURI, ":")
		firstIndex := strings.Index(req.RequestURI, ":")
		// compatible
		if firstIndex != lastIndex {
			req.RequestURI = "[" + req.RequestURI[:lastIndex] + "]" + req.RequestURI[lastIndex:]
		}
		a, err := common.NewNetAddr("tcp", req.RequestURI)
		if err != nil {
			return nil, err
		}
		req.NetAddr = a
		return req, nil
	}
	u, err := url.Parse(req.RequestURI)
	if err != nil {
		return nil, err
	}
	req.TargetURL = u
	if u.Host == "" {
		return nil, errors.New("read request: host is empty")
	}
	var port string
	switch u.Scheme {
	case "http":
		port = "80"
	case "https":
		port = "443"
	default:
		return nil, fmt.Errorf("read request: wrong scheme %s", u.Scheme)
	}
	if p := u.Port(); p != "" {
		port = p
	}
	hostName := u.Hostname()
	if strings.IndexByte(hostName, ':') > 0 {
		req.NetAddr, err = common.NewNetAddr("tcp6", "["+hostName+"]:"+port)
	} else {
		req.NetAddr, err = common.NewNetAddr("tcp", hostName+":"+port)
	}
	if err != nil {
		return nil, err
	}
	return req, nil
}

func WriteRequest(w io.Writer, req *Request) error {
	b, err := httputil.DumpRequest(req.Request, false)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func WriteResponse(w io.Writer, req *Request, pass bool) error {
	if !pass {
		_, err := w.Write([]byte(
			"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Access to the internal site\" charset=\"UTF-8\"\r\nContent-Length: 0\r\n\r\n",
		))
		return err
	}
	if req.Request.Method == http.MethodConnect {
		_, err := w.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		return err
	}
	return nil
}

func ReadResponse(r *bufio.Reader) (*http.Response, error) {
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp, fmt.Errorf("unexpected response status: %s", resp.Status)
	}
	return resp, nil
}

// Only Connect
func NewRequest(addr *common.NetAddr) *Request {
	host := addr.Address()
	return &Request{
		Request: &http.Request{
			Method:     http.MethodConnect,
			Host:       host,
			RequestURI: host,
		},
		NetAddr: addr,
	}
}

func RestoreRequest(req *Request) *http.Request {
	req.Request.URL = req.TargetURL
	req.Request.RequestURI = req.TargetURL.RawPath
	req.Request.Host = req.TargetURL.Host
	return req.Request
}

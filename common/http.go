package common

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"lite/pkg"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func SendFakeNginxResponse(w http.ResponseWriter, statusCode int, content string) error {
	statusText := http.StatusText(statusCode)
	status := strconv.Itoa(statusCode)
	if statusText != "" {
		status += " " + statusText
	}
	contentType := "text/plain; charset=utf-8"
	if content == "" && statusText != "" && statusCode >= http.StatusBadRequest {
		contentType = "text/html"
		content = "<html>\r\n<head><title>" + status + "</title></head>\r\n<body>\r\n<center><h1>" + status + "</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
	}
	w.Header().Set("Server", "nginx")
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(statusCode)
	_, err := w.Write([]byte(content))
	return err
}

var (
	_ http.Handler = (*HTTPReverseProxyHandler)(nil)
	_ http.Handler = (*HTTPFileHandler)(nil)
)

type HTTPReverseProxyHandler struct {
	client *http.Client
	dialer *net.Dialer
	url    *url.URL
	addr   *NetAddr
}

func NewHTTPReverseProxyHandler(u string) (*HTTPReverseProxyHandler, error) {
	target, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, errors.New("unsupported scheme")
	}
	if target.Host == "" {
		return nil, errors.New("host cannot be empty")
	}
	d := &net.Dialer{
		Timeout: 10 * time.Second,
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()

	// it will ensure that when the HTTP client is GCed
	// the runtime will close the idle connections (so that they won't leak)
	// this function was adopted from Hashicorp's go-cleanhttp package
	runtime.SetFinalizer(&tr, func(transportInt **http.Transport) {
		(*transportInt).CloseIdleConnections()
	})

	tr.DisableCompression = true
	tr.DialContext = d.DialContext
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	port := target.Port()
	if port == "" {
		if target.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	hostname := target.Hostname()
	addr, err := NewNetAddr("tcp", net.JoinHostPort(hostname, port))
	if err != nil {
		return nil, err
	}
	return &HTTPReverseProxyHandler{
		dialer: d,
		client: &http.Client{
			Transport: tr,
			Timeout:   60 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		url:  target,
		addr: addr,
	}, nil
}

func (h *HTTPReverseProxyHandler) proxyHTTP(w http.ResponseWriter, req *http.Request) error {
	resp, err := h.client.Do(req)
	if err != nil {
		SendFakeNginxResponse(w, http.StatusBadGateway, "")
		return err
	}
	defer resp.Body.Close()
	wH := w.Header()
	for k, v := range resp.Header {
		wH[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	buf := GetBuffer(16 * 1024)
	defer PutBuffer(buf)
	_, err = io.CopyBuffer(w, resp.Body, buf)
	return err
}

func (h *HTTPReverseProxyHandler) dial() (net.Conn, error) {
	c, err := h.dialer.Dial("tcp", h.addr.Address())
	if err != nil {
		return nil, err
	}
	if h.url.Scheme == "https" {
		c = tls.Client(c, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         h.addr.Hostname(),
			NextProtos:         []string{"http/1.1"},
		})
	}
	return c, nil
}

// Only support http1
func (h *HTTPReverseProxyHandler) proxyWebsocket(w http.ResponseWriter, req *http.Request) error {
	if req.ProtoMajor != 1 {
		SendFakeNginxResponse(w, http.StatusBadRequest, "")
		return NewErrorWithRequest(req, "websocket only support http1")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		SendFakeNginxResponse(w, http.StatusBadGateway, "")
		return NewErrorWithRequest(req, "failed to assert http.Hijacker")
	}
	c, rw, err := hj.Hijack()
	if err != nil {
		SendFakeNginxResponse(w, http.StatusBadGateway, "")
		return NewErrorWithRequest(req, "failed to hijack connection: "+err.Error())
	}
	defer c.Close()
	c = NewCacheConn(c).AddCacheFromReader(rw.Reader).Unwrap()
	targetC, err := h.dial()
	if err != nil {
		return err
	}
	defer targetC.Close()
	_, err = fmt.Fprintf(targetC, "%s %s HTTP/1.1\r\n", req.Method, req.URL.RequestURI())
	if err != nil {
		return err
	}
	err = req.Header.Write(targetC)
	if err != nil {
		return err
	}
	_, err = targetC.Write([]byte("\r\n"))
	if err != nil {
		return err
	}
	return ConnectStream(c, targetC, 16*1024)
}

func (handler *HTTPReverseProxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	req.Header.Del("Host")
	req.RequestURI = ""
	req.Host = handler.url.Host
	req.URL.Host = handler.url.Host
	req.URL.Scheme = handler.url.Scheme
	removeUnsafeHeaders(req.Header)
	if strings.Contains(strings.ToLower(req.Header.Get("Upgrade")), "websocket") {
		handler.proxyWebsocket(w, req)
	} else {
		handler.proxyHTTP(w, req)
	}
}

func (h *HTTPReverseProxyHandler) ProxyURL() *url.URL {
	return h.url
}

func removeUnsafeHeaders(h http.Header) {
	for _, k := range []string{
		"CF-Connecting-IP",
		"CF-Connecting-IPv6",
		"CF-EW-Via",
		"CF-Pseudo-IPv4",
		"True-Client-IP",
		"X-Forwarded-For",
		"X-Forwarded-Proto",
		"CF-RAY",
		"CF-IPCountry",
		"CF-Visitor",
		"CDN-Loop",
		"CF-Worker",
	} {
		h.Del(k)
	}
}

type HTTPFileHandler struct {
	path       string
	fileServer http.Handler
}

func NewHTTPFileHandler(path string) *HTTPFileHandler {
	path = filepath.Clean(path)
	return &HTTPFileHandler{
		path:       path,
		fileServer: http.FileServer(http.Dir(path)),
	}
}

func (h *HTTPFileHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	p := filepath.Join(h.path, req.URL.Path)
	if h.path != "." && !strings.HasPrefix(p, h.path) {
		SendFakeNginxResponse(w, http.StatusNotFound, "")
		return
	}
	if info, err := os.Stat(p); err == nil {
		if info.IsDir() {
			indexP := path.Join(p, "index.html")
			if info, err := os.Stat(indexP); err != nil || info.IsDir() {
				SendFakeNginxResponse(w, http.StatusForbidden, "")
				return
			}
		}
	} else {
		SendFakeNginxResponse(w, http.StatusNotFound, "")
		return
	}
	w.Header().Set("Server", "nginx")
	h.fileServer.ServeHTTP(w, req)
}

func (h *HTTPFileHandler) FilePath() string {
	return h.path
}

func NewReverseProxyOrFileHandler(s string) (http.Handler, error) {
	if pkg.IsURL(s) {
		return NewHTTPReverseProxyHandler(s)
	} else {
		return NewHTTPFileHandler(s), nil
	}
}

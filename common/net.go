package common

import (
	"bufio"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

func JoinAddrPort(addr string, port uint16) string {
	p := strconv.FormatUint(uint64(port), 10)
	if strings.IndexByte(addr, ':') > 0 {
		return "[" + addr + "]:" + p
	}
	return addr + ":" + p
}

func IPToAddr(ip net.IP) *netip.Addr {
	if ip == nil {
		return nil
	}
	var addr netip.Addr
	if ip4 := ip.To4(); ip4 != nil {
		addr = netip.AddrFrom4([4]byte(ip4))
	} else {
		addr = netip.AddrFrom16([16]byte(ip.To16()))
	}
	return &addr
}

// Ref: https://github.com/golang/go/blob/fb2c88147d0aab656b7a8ae109b3d1241de402ab/src/net/dnsclient.go
func IsDomainName(s string) bool {
	// The root domain name is valid. See golang.org/issue/45715.
	if s == "." {
		return true
	}

	// See RFC 1035, RFC 3696.
	// Presentation format has dots before every label except the first, and the
	// terminal empty label is optional here because we assume fully-qualified
	// (absolute) input. We must therefore reserve space for the first and last
	// labels' length octets in wire format, where they are necessary and the
	// maximum total length is 255.
	// So our _effective_ maximum is 253, but 254 is not rejected if the last
	// character is a dot.
	l := len(s)
	if l == 0 || l > 254 || l == 254 && s[l-1] != '.' {
		return false
	}

	last := byte('.')
	nonNumeric := false // true once we've seen a letter or hyphen
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			nonNumeric = true
			partlen++
		case '0' <= c && c <= '9':
			// fine
			partlen++
		case c == '-':
			// Byte before dash cannot be dot.
			if last == '.' {
				return false
			}
			partlen++
			nonNumeric = true
		case c == '.':
			// Byte before dot cannot be dot, dash.
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}

	return nonNumeric
}

func ParseAddress(address string) (string, uint16, *netip.Addr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, nil, err
	}
	portUint, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return "", 0, nil, err
	}
	var ip *netip.Addr
	host, ip, err = ParseHost(host)
	return host, uint16(portUint), ip, err
}

func ParseHost(host string) (string, *netip.Addr, error) {
	ip := net.ParseIP(host)
	if ip == nil && !IsDomainName(host) {
		return "", nil, errors.New("invalid host: " + host)
	}
	return host, IPToAddr(ip), nil
}

var _ net.Addr = (*NetAddr)(nil)

type NetAddr struct {
	Net  string
	IP   *netip.Addr
	FQDN string
	Port uint16
}

func (a *NetAddr) Clone() *NetAddr {
	addr := &NetAddr{
		Net:  a.Net,
		FQDN: a.FQDN,
		Port: a.Port,
	}
	if a.IP != nil {
		ip := *a.IP
		addr.IP = &ip
	}
	return addr
}

func (a *NetAddr) SetNetwork(network string) *NetAddr {
	a.Net = network
	return a
}

func (a *NetAddr) SetIP(ip net.IP) *NetAddr {
	if ip.To4() != nil {
		return a.SetIPv4(ip)
	} else {
		return a.SetIPv6(ip)
	}
}

func (a *NetAddr) SetIPv4(ip net.IP) *NetAddr {
	ipAddr := netip.AddrFrom4([4]byte(ip.To4()))
	a.IP = &ipAddr
	return a
}

func (a *NetAddr) SetIPv6(ip net.IP) *NetAddr {
	ipAddr := netip.AddrFrom16([16]byte(ip))
	a.IP = &ipAddr
	return a
}

func (a *NetAddr) Network() string {
	return a.Net
}

func (a *NetAddr) String() string {
	return a.Address()
}

func (a *NetAddr) Hostname() string {
	if a.IP != nil {
		return a.IP.String()
	}
	return a.FQDN
}

func (a *NetAddr) Address() string {
	return JoinAddrPort(a.Hostname(), a.Port)
}

func (a *NetAddr) IsTCP() bool {
	return a.Net == "tcp" || a.Net == "tcp4" || a.Net == "tcp6"
}

func (a *NetAddr) IsUDP() bool {
	return a.Net == "udp" || a.Net == "udp4" || a.Net == "udp6"
}

func (a *NetAddr) IsIP() bool {
	return a.IP != nil
}

func (a *NetAddr) IsIPv4() bool {
	return a.IP != nil && a.IP.Is4()
}

func (a *NetAddr) IsIPv6() bool {
	return a.IP != nil && a.IP.Is6()
}

func (a *NetAddr) IsFQDN() bool {
	return a.FQDN != ""
}

func NewNetAddr(network, address string) (*NetAddr, error) {
	a := &NetAddr{}
	switch network {
	case "tcp", "tcp4", "tcp6":
		a.Net = "tcp"
	case "udp", "udp4", "udp6":
		a.Net = "udp"
	default:
		return nil, net.UnknownNetworkError(network)
	}
	host, port, ip, err := ParseAddress(address)
	if err != nil {
		return nil, err
	}
	a.Port = port
	a.IP = ip
	if ip == nil {
		a.FQDN = host
	} else {
		a.IP = ip
	}
	return a, nil
}

func ConvertAddr(addr net.Addr) (*NetAddr, error) {
	if a, ok := addr.(*NetAddr); ok {
		return a, nil
	}
	return NewNetAddr(addr.Network(), addr.String())
}

type CacheConn struct {
	net.Conn
	cacheList [][]byte
}

func (c *CacheConn) Read(b []byte) (int, error) {
	for i := range len(c.cacheList) {
		if len(c.cacheList[i]) > 0 {
			n := copy(b, c.cacheList[i])
			c.cacheList[i] = c.cacheList[i][n:]
			if len(c.cacheList[i]) == 0 {
				c.cacheList[i] = nil
			}
			return n, nil
		}
	}
	if c.cacheList != nil {
		c.cacheList = nil
	}
	return c.Conn.Read(b)
}

func NewCacheConn(conn net.Conn) *CacheConn {
	return &CacheConn{
		Conn: conn,
	}
}

func (c *CacheConn) AddCache(b []byte) *CacheConn {
	if len(b) > 0 {
		c.cacheList = append(c.cacheList, b)
	}
	return c
}

func (c *CacheConn) AddCacheFromReader(r *bufio.Reader) *CacheConn {
	b, _ := r.Peek(r.Buffered())
	return c.AddCache(b)
}

func (c *CacheConn) Unwrap() net.Conn {
	if len(c.cacheList) == 0 {
		return c.Conn
	}
	return c
}

func NewReaderSizeFromConn(conn net.Conn, size int) (reader *bufio.Reader, isBufferedConn bool) {
	if v, ok := conn.(*BufferedConn); ok {
		return v.GetReader(), true
	}
	return bufio.NewReaderSize(conn, size), false
}

type BufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func NewBufferedConnSize(conn net.Conn, size int) *BufferedConn {
	if v, ok := conn.(*BufferedConn); ok {
		return v
	}
	return &BufferedConn{Conn: conn, reader: bufio.NewReaderSize(conn, size)}
}

func (c *BufferedConn) GetReader() *bufio.Reader {
	return c.reader
}

func (c *BufferedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

var remoteUDP6Addr = &net.UDPAddr{IP: net.ParseIP("2400:3200::1"), Port: 53}

func CheckIPv6ByDial() bool {
	c, err := net.DialUDP("udp6", nil, remoteUDP6Addr)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

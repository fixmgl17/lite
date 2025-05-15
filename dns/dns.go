package dns

import (
	"context"
	"lite/common"
	"net"
	"time"

	"github.com/dgraph-io/ristretto/v2"
)

var _ Resolver = (*Client)(nil)

type Client struct {
	resolver Resolver
	ttl      time.Duration
	urlStr   string
	// nil if ttl <= 0
	cache             *ristretto.Cache[string, []net.IP]
	OnLookupIP        func(serverURL, host string, requireIPv6 bool, ipList []net.IP, err error)
	OnLookupIPByCache func(host string, requireIPv6 bool, ipList []net.IP, ok bool)
}

// Scheme: "udp", "https", "system"
func NewClient(urlStr string, ttl time.Duration) (client *Client, err error) {
	if ttl <= 0 {
		ttl = 0
	}
	if urlStr == "" {
		urlStr = "system://"
	}
	resolver, err := NewResolver(urlStr)
	if err != nil {
		return nil, err
	}
	client = &Client{
		resolver: resolver,
		ttl:      ttl,
		urlStr:   urlStr,
	}
	if ttl > 0 {
		client.cache, err = ristretto.NewCache(&ristretto.Config[string, []net.IP]{NumCounters: 4 * 1e5, MaxCost: 2 * (1 << 20), BufferItems: 64})
		if err != nil {
			return nil, err
		}
	}
	return client, nil
}

// Shallow clone
func (client *Client) Clone() *Client {
	newClient := *client
	return &newClient
}

func (client *Client) storeIP(host string, isIPv6 bool, ipList []net.IP) {
	if client.ttl <= 0 {
		return
	}
	var key string
	if isIPv6 {
		key = "ip6:" + host
	} else {
		key = "ip4:" + host
	}
	client.cache.SetWithTTL(key, ipList, 0, client.ttl)
}

func (client *Client) LookupIPByCache(host string, requireIPv6 bool) (ipList []net.IP, ok bool) {
	if client.ttl <= 0 {
		return
	}
	var key string
	if requireIPv6 {
		key = "ip6:" + host
	} else {
		key = "ip4:" + host
	}
	ipList, ok = client.cache.Get(key)
	if client.OnLookupIPByCache != nil {
		client.OnLookupIPByCache(host, requireIPv6, ipList, ok)
	}
	return
}

func (client *Client) lookupIP(ctx context.Context, host string, requireIPv6 bool) (ipList []net.IP, err error) {
	defer func() {
		if err == nil || IsErrNXDomain(err) {
			client.storeIP(host, requireIPv6, ipList)
		}
	}()
	if requireIPv6 {
		ipList, err = client.resolver.LookupIPv6(ctx, host)
	} else {
		ipList, err = client.resolver.LookupIPv4(ctx, host)
	}
	if client.OnLookupIP != nil {
		client.OnLookupIP(client.urlStr, host, requireIPv6, ipList, err)
	}
	return
}

func (client *Client) LookupIPv4(ctx context.Context, host string) ([]net.IP, error) {
	ipv4List, ok := client.LookupIPByCache(host, false)
	if ok {
		if len(ipv4List) == 0 {
			return nil, ErrNXDomain
		}
		return ipv4List, nil
	}
	return client.lookupIP(ctx, host, false)
}

func (client *Client) LookupIPv6(ctx context.Context, host string) ([]net.IP, error) {
	ipv6List, ok := client.LookupIPByCache(host, true)
	if ok {
		if len(ipv6List) == 0 {
			return nil, ErrNXDomain
		}
		return ipv6List, nil
	}
	return client.lookupIP(ctx, host, true)
}

func (client *Client) LookupIP(ctx context.Context, host string) (ipv4List []net.IP, ipv6List []net.IP, err error) {
	var ok4, ok6 bool
	ipv4List, ok4 = client.LookupIPByCache(host, false)
	ipv6List, ok6 = client.LookupIPByCache(host, true)
	if !ok4 && !ok6 {
		ipv4List, ipv6List, err = lookupIPViaResolver(ctx, client, host)
	} else if !ok4 {
		ipv4List, err = client.lookupIP(ctx, host, false)
	} else if !ok6 {
		ipv6List, err = client.lookupIP(ctx, host, true)
	}
	return
}

func (client *Client) Close() error {
	return common.TryToClose(client.resolver)
}

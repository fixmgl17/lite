package dns

import (
	"context"
	"errors"
	"net"
)

var ErrNXDomain = errors.New("non-existent domain")

func IsErrNXDomain(err error) bool {
	if err == ErrNXDomain {
		return true
	}
	return errors.Is(err, ErrNXDomain)
}

type _Resolver interface {
	LookupIPv4(ctx context.Context, host string) ([]net.IP, error)
	LookupIPv6(ctx context.Context, host string) ([]net.IP, error)
}

type Resolver interface {
	_Resolver
	LookupIP(ctx context.Context, host string) ([]net.IP, []net.IP, error)
}

type lookupResult struct {
	ipList []net.IP
	err    error
}

// Returns an error only if the list is empty for both ipv4 and ipv6
func lookupIPViaResolver(ctx context.Context, r _Resolver, host string) ([]net.IP, []net.IP, error) {
	ch4, ch6 := make(chan lookupResult, 1), make(chan lookupResult, 1)
	go func() {
		ipv4List, err := r.LookupIPv4(ctx, host)
		ch4 <- lookupResult{ipList: ipv4List, err: err}
	}()
	go func() {
		ipv6List, err := r.LookupIPv6(ctx, host)
		ch6 <- lookupResult{ipv6List, err}
	}()
	result4, result6 := <-ch4, <-ch6
	if result4.err != nil && result6.err != nil {
		err := ErrNXDomain
		if !IsErrNXDomain(result4.err) {
			err = result4.err
		} else if !IsErrNXDomain(result6.err) {
			err = result6.err
		}
		return nil, nil, err
	}
	return result4.ipList, result6.ipList, nil
}

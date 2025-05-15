package pkg

import (
	"net/url"
	"slices"
)

func IsURL(s string, schemes ...string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return false
	}
	if len(schemes) < 1 {
		schemes = []string{"http", "https"}
	}
	return slices.Contains(schemes, u.Scheme)
}

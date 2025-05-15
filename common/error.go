package common

import (
	"errors"
	"net/http"
	"time"
)

func NewErrorWithRequest(r *http.Request, reason string) error {
	return errors.New("accept " + r.Proto + " request from " + r.RemoteAddr + ": " + reason)
}

func RunWithTimeout(t time.Duration, f ...func() error) error {
	ch := make(chan error, len(f))
	for i := range f {
		go func() {
			ch <- f[i]()
		}()
	}
	select {
	case <-time.After(t):
		return nil
	case err := <-ch:
		return err
	}
}

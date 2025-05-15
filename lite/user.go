package lite

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

type User struct {
	ID [16]byte

	lastTime   time.Time
	readBytes  atomic.Int64
	writeBytes atomic.Int64

	ExpireTime time.Time

	readLimiter  *rate.Limiter
	writeLimiter *rate.Limiter
}

func (u *User) ReadBytesRateLimit() int {
	if limiter := u.readLimiter; limiter != nil {
		return limiter.Burst()
	}
	return 0
}

func (u *User) WriteBytesRateLimit() int {
	if limiter := u.writeLimiter; limiter != nil {
		return limiter.Burst()
	}
	return 0
}

func (u *User) SetReadBytesRateLimit(limit int) {
	if limit > 0 {
		u.readLimiter = rate.NewLimiter(rate.Limit(limit), limit)
	} else {
		u.readLimiter = nil
	}
}

func (u *User) SetWriteBytesRateLimit(limit int) {
	if limit > 0 {
		u.writeLimiter = rate.NewLimiter(rate.Limit(limit), limit)
	} else {
		u.writeLimiter = nil
	}
}

func (u *User) ReadBytes() int64 {
	return u.readBytes.Load()
}

func (u *User) WriteBytes() int64 {
	return u.writeBytes.Load()
}

func (u *User) AddWriteBytes(n int64) {
	u.writeBytes.Add(n)
}

func (u *User) AddReadBytes(n int64) {
	u.readBytes.Add(n)
}

func (u *User) LastTime() time.Time {
	return u.lastTime
}

func (u *User) ForceExpire() {
	u.ExpireTime = (time.Time{}).Add(time.Second)
}

func (u *User) CheckExpired() error {
	if !u.ExpireTime.IsZero() && time.Now().After(u.ExpireTime) {
		return fmt.Errorf("user id %02X expired", u.ID)
	} else {
		return nil
	}
}

func (u *User) Effective() bool {
	return !u.ExpireTime.IsZero() || u.readLimiter != nil || u.writeLimiter != nil
}

func (u *User) Wrap(conn net.Conn) *UserConn {
	u.lastTime = time.Now()
	c := &UserConn{
		Conn: conn,
		User: u,
	}
	return c
}

type UserConn struct {
	net.Conn
	User         *User
	DisableCount bool
}

func (c *UserConn) SetDisableCount(v bool) *UserConn {
	c.DisableCount = v
	return c
}

func waitN(l *rate.Limiter, n int) error {
	if l == nil || n == 0 {
		return nil
	}
	burst := l.Burst()
	ctx := context.Background()
	var err error
	for n > 0 {
		if n > burst {
			err = l.WaitN(ctx, burst)
		} else {
			err = l.WaitN(ctx, n)
		}
		// should not happen
		if err != nil {
			return err
		}
		n -= burst
	}
	return nil
}

func (c *UserConn) Read(b []byte) (int, error) {
	if err := c.User.CheckExpired(); err != nil {
		return 0, err
	}
	if err := waitN(c.User.readLimiter, len(b)); err != nil {
		// should not happen
		return 0, err
	}
	n, err := c.Conn.Read(b)
	if err == nil && !c.DisableCount {
		c.User.AddReadBytes(int64(n))
	}
	return n, err
}

func (c *UserConn) Write(b []byte) (int, error) {
	if err := c.User.CheckExpired(); err != nil {
		return 0, err
	}
	if err := waitN(c.User.writeLimiter, len(b)); err != nil {
		// should not happen
		return 0, err
	}
	n, err := c.Conn.Write(b)
	if err == nil && !c.DisableCount {
		c.User.AddWriteBytes(int64(n))
	}
	return n, err
}

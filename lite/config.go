package lite

import (
	"encoding/hex"
	"fmt"
	"lite/common/uuid"
	"lite/pkg"
	"time"
)

type DialerConfig struct {
	User UserConfig `json:"user"`
}

type ServerConfig struct {
	Users []UserConfig `json:"users"`
}

type UserConfig struct {
	ID             string `json:"id"`
	ExpireTime     string `json:"expire_time"`
	ReadRateLimit  string `json:"read_rate_limit"`
	WriteRateLimit string `json:"write_rate_limit"`
}

func ParseStringID(idStr string) (id [16]byte, err error) {
	if len(idStr) == 32 {
		var b []byte
		b, err = hex.DecodeString(idStr)
		copy(id[:], b)
	} else {
		id, err = uuid.ParseString(idStr)
	}
	if err != nil {
		err = fmt.Errorf("parse id %s: %v", idStr, err)
	}
	return
}

func (config *UserConfig) ToUser() (*User, error) {
	id, err := ParseStringID(config.ID)
	if err != nil {
		return nil, err
	}
	user := &User{ID: id}
	if config.ReadRateLimit != "" {
		limit, err := pkg.ParseSize(config.ReadRateLimit)
		if err != nil {
			return nil, fmt.Errorf("parse read rate limit %s: %v", config.ReadRateLimit, err)
		}
		user.SetReadBytesRateLimit(int(limit))
	}
	if config.WriteRateLimit != "" {
		limit, err := pkg.ParseSize(config.WriteRateLimit)
		if err != nil {
			return nil, fmt.Errorf("parse write rate limit %s: %v", config.WriteRateLimit, err)
		}
		user.SetWriteBytesRateLimit(int(limit))
	}
	if config.ExpireTime != "" {
		var err error
		var expiredTime time.Time
		for _, layout := range []string{time.RFC3339, time.DateOnly, time.DateTime, "2006/01/02 15:04:05"} {
			expiredTime, err = time.Parse(layout, config.ExpireTime)
			if err == nil {
				break
			}
		}
		if err != nil {
			return nil, fmt.Errorf("parse expired time %s: invalid layout", config.ExpireTime)
		}
		user.ExpireTime = expiredTime
	}
	return user, nil
}

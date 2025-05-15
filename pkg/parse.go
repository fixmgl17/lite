package pkg

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Parses a string into a size in bytes. e.g. "1.2MB" -> int64(1.2 * 1024 * 1024)
func ParseSize(s string) (int64, error) {
	s = strings.TrimRight(strings.ToUpper(s), "B")
	if len(s) == 0 {
		return 0, errors.New("invalid size")
	}
	var multiplier float64
	switch s[len(s)-1] {
	case 'K':
		multiplier = 1024
	case 'M':
		multiplier = 1024 * 1024
	case 'G':
		multiplier = 1024 * 1024 * 1024
	case 'T':
		multiplier = 1024 * 1024 * 1024 * 1024
	default:
		multiplier = 1
	}
	if multiplier != 1 {
		s = s[:len(s)-1]
	}
	s = strings.TrimRight(s, " ")
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, err
	}
	return int64(v * multiplier), nil
}

type TimeClock struct {
	Hour   int
	Minute int
	Second int
}

// -1 if t < c, 0 if t == c, 1 if t > c
func (t *TimeClock) Compare(c *TimeClock) int {
	if t.Hour > c.Hour {
		return 1
	} else if t.Hour < c.Hour {
		return -1
	}
	if t.Minute > c.Minute {
		return 1
	} else if t.Minute < c.Minute {
		return -1
	}
	if t.Second > c.Second {
		return 1
	} else if t.Second < c.Second {
		return -1
	}
	return 0
}

func (t *TimeClock) IsValid() bool {
	return t.Hour >= 0 && t.Minute >= 0 && t.Second >= 0 && t.Hour <= 23 && t.Minute <= 59 && t.Second <= 59
}

func ParseTimeRange(t string) (from, to *TimeClock, err error) {
	t = strings.ReplaceAll(t, " ", "")
	s := strings.Split(t, "-")
	if len(s) != 2 {
		return nil, nil, errors.New("invalid time range")
	}
	c := make([]*TimeClock, 2)
	for i, v := range s {
		if v == "" {
			continue
		}
		var layout string
		switch strings.Count(v, ":") {
		case 0:
			layout = "15"
			if len(v) == 1 {
				v = "0" + v
			}
		case 1:
			layout = "15:04"
		case 2:
			layout = "15:04:05"
		default:
			return nil, nil, errors.New("time range: invalid time format")
		}
		t, err := time.Parse(layout, v)
		if err != nil {
			return nil, nil, fmt.Errorf("time range: %v", err)
		}
		c[i] = &TimeClock{
			Hour:   t.Hour(),
			Minute: t.Minute(),
			Second: t.Second(),
		}
		if !c[i].IsValid() {
			return nil, nil, errors.New("time range: invalid value")
		}
	}
	return c[0], c[1], nil
}

func ParsePortRange(s string) ([]uint16, error) {
	list := slices.DeleteFunc(strings.Split(s, ","), func(v string) bool {
		return v == ""
	})
	portMap := make(map[uint16]struct{})
	for _, v := range list {
		ss := strings.Split(v, "-")
		switch len(ss) {
		case 1:
			v, err := strconv.ParseUint(v, 10, 16)
			if err != nil {
				return nil, err
			}
			portMap[uint16(v)] = struct{}{}
		case 2:
			var start, end uint16
			if ss[0] == "" {
				start = 0
			} else {
				v, err := strconv.ParseUint(ss[0], 10, 16)
				if err != nil {
					return nil, err
				}
				start = uint16(v)
			}
			if ss[1] == "" {
				end = 65535
			} else {
				v, err := strconv.ParseUint(ss[1], 10, 16)
				if err != nil {
					return nil, err
				}
				end = uint16(v)
			}
			if start > end {
				return nil, errors.New("invalid port range")
			}
			for i := start; i <= end; i++ {
				portMap[i] = struct{}{}
			}
		default:
			return nil, errors.New("invalid port range")
		}
	}
	var ports []uint16
	for k := range portMap {
		ports = append(ports, k)
	}
	slices.Sort(ports)
	return ports, nil
}

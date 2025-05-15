package pkg

import "fmt"

func FormatSize[T int | int32 | int64 | uint | uint32 | uint64](v T) string {
	cb := func(v float64, unit string) string {
		integer := int64(v)
		if float64(integer) == float64(v) {
			return fmt.Sprintf("%d%s", integer, unit)
		} else {
			return fmt.Sprintf("%.2f%s", v, unit)
		}
	}
	size := int64(v)
	n := float64(size)
	if size < 1024 {
		return cb(n, "B")
	} else if size < 1024*1024 {
		return cb(n/1024, "KB")
	} else if size < 1024*1024*1024 {
		return cb(n/(1024*1024), "MB")
	} else if size < 1024*1024*1024*1024 {
		return cb(n/(1024*1024*1024), "GB")
	} else {
		return cb(n/(1024*1024*1024*1024), "TB")
	}
}

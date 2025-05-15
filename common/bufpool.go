package common

import (
	"sync"
)

var (
	bufPools = []struct {
		size int
		pool sync.Pool
	}{
		{
			size: 256,
			pool: sync.Pool{
				New: func() any {
					b := make([]byte, 256)
					return b
				},
			},
		},
		{
			size: 270,
			pool: sync.Pool{
				New: func() any {
					b := make([]byte, 270)
					return b
				},
			},
		},
		{
			size: 512,
			pool: sync.Pool{
				New: func() any {
					b := make([]byte, 512)
					return b
				},
			},
		},
		{
			size: 520,
			pool: sync.Pool{
				New: func() any {
					b := make([]byte, 520)
					return b
				},
			},
		},
		{
			size: 1024,
			pool: sync.Pool{
				New: func() any {
					b := make([]byte, 1024)
					return b
				},
			},
		},
		{
			size: 4 * 1024,
			pool: sync.Pool{
				New: func() any {
					b := make([]byte, 4*1024)
					return b
				},
			},
		},
		{
			size: 16 * 1024,
			pool: sync.Pool{
				New: func() any {
					b := make([]byte, 16*1024)
					return b
				},
			},
		},
		{
			size: 32 * 1024,
			pool: sync.Pool{
				New: func() any {
					b := make([]byte, 32*1024)
					return b
				},
			},
		},
		{
			size: 64 * 1024,
			pool: sync.Pool{
				New: func() any {
					b := make([]byte, 64*1024)
					return b
				},
			},
		},
	}
)

// Pool size supported: 256, 270, 512, 520, 1024, 4*1024, 16*1024, 32*1024, 64*1024
func GetBuffer(size int) []byte {
	for i := range bufPools {
		if size <= bufPools[i].size {
			b := bufPools[i].pool.Get().([]byte)
			return b[:size]
		}
	}
	b := make([]byte, size)
	return b
}

// Pool size supported: 128, 256, 270, 512, 520, 1024, 4*1024, 16*1024, 32*1024, 64*1024
func PutBuffer(b []byte) {
	for i := range bufPools {
		if cap(b) == bufPools[i].size {
			bufPools[i].pool.Put(b)
			return
		}
	}
}

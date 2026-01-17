package transport

import "sync"

// Buffer Pools
// We use two sizes:
// 1. Small (2KB): For standard MTU packets (1500 bytes)
// 2. Large (64KB): For UDP batches or large reads (if needed)

var (
	pool2K = sync.Pool{
		New: func() interface{} {
			return make([]byte, 2048)
		},
	}
	pool64K = sync.Pool{
		New: func() interface{} {
			return make([]byte, 65535)
		},
	}
)

// GetBuffer2K returns a 2KB buffer from the pool.
func GetBuffer2K() []byte {
	return pool2K.Get().([]byte)
}

// PutBuffer2K returns a 2KB buffer to the pool.
func PutBuffer2K(b []byte) {
	if cap(b) < 2048 {
		return // Discard if resized too small
	}
	pool2K.Put(b[:2048]) // Reset len to cap
}

// GetBuffer64K returns a 64KB buffer from the pool.
func GetBuffer64K() []byte {
	return pool64K.Get().([]byte)
}

// PutBuffer64K returns a 64KB buffer to the pool.
func PutBuffer64K(b []byte) {
	if cap(b) < 65535 {
		return
	}
	pool64K.Put(b[:65535])
}

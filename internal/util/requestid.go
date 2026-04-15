package util

import (
	"sync/atomic"
	"time"
)

// requestIDCounter is a monotonic counter for generating unique request IDs.
// Combined with the process start time, this produces globally unique IDs
// without requiring external dependencies (UUID libraries) or crypto/rand.
var requestIDCounter uint64

// initTimestamp is the Unix nanosecond timestamp at process start,
// used as the high bits of the request ID to ensure uniqueness across restarts.
var initTimestamp = uint64(time.Now().UnixNano())

// GenerateRequestID returns a unique 16-character hex string for a DNS request.
// Format: 12 hex chars from counter + process start time entropy.
// The ID is fast to generate (single atomic increment + fmt.Sprintf)
// and unique within a single process lifetime.
func GenerateRequestID() string {
	n := atomic.AddUint64(&requestIDCounter, 1)
	// Mix counter with init timestamp for cross-restart uniqueness
	id := (n << 20) ^ (n >> 44) ^ initTimestamp
	// Format as 16 hex chars
	const hex = "0123456789abcdef"
	var buf [16]byte
	for i := 15; i >= 0; i-- {
		buf[i] = hex[id&0xf]
		id >>= 4
	}
	return string(buf[:])
}

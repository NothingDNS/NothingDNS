package raft

import (
	"crypto/rand"
	"math/big"
	"sync"
)

// LockedRand provides thread-safe random number generation.
type LockedRand struct {
	mu sync.Mutex
}

// NewLockedRand creates a new LockedRand with a cryptographically secure seed.
func NewLockedRand() *LockedRand {
	return &LockedRand{}
}

// Int63n returns a random int64 in [0, n).
func (r *LockedRand) Int63n(n int64) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Use crypto/rand for secure random number generation
	if n <= 0 {
		return 0
	}

	// Generate a random big int and take modulo n
	max := new(big.Int).SetInt64(n)
	result, err := rand.Int(rand.Reader, max)
	if err != nil {
		// Fallback (should never happen with crypto/rand)
		return 0
	}
	return result.Int64()
}

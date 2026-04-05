package raft

import (
	"math/rand"
	"sync"
)

// LockedRand provides thread-safe random number generation.
type LockedRand struct {
	mu  sync.Mutex
	rng *rand.Rand
}

// NewLockedRand creates a new LockedRand with a random seed.
func NewLockedRand() *LockedRand {
	return &LockedRand{
		rng: rand.New(rand.NewSource(rand.Int63())),
	}
}

// Int63n returns a random int64 in [0, n).
func (r *LockedRand) Int63n(n int64) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rng.Int63n(n)
}

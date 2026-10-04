package dnscookie

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func TestFailedRotationPreservesState(t *testing.T) {
	original := rand.Reader
	defer func() { rand.Reader = original }()
	for _, size := range []int{0, 1, 15} {
		jar := &CookieJar{current: ServerSecret{1}, previous: ServerSecret{2}, hasPrevious: true, lastRotation: time.Unix(100, 0)}
		current, previous, hasPrevious, lastRotation := jar.current, jar.previous, jar.hasPrevious, jar.lastRotation
		rand.Reader = bytes.NewReader(bytes.Repeat([]byte{3}, size))
		if err := jar.RotateSecret(); err == nil {
			t.Fatalf("size %d: expected failure", size)
		}
		if jar.current != current || jar.previous != previous || jar.hasPrevious != hasPrevious || jar.lastRotation != lastRotation {
			t.Fatalf("size %d: failed rotation changed state", size)
		}
		rand.Reader = bytes.NewReader(bytes.Repeat([]byte{4}, 16))
		if err := jar.RotateSecret(); err != nil {
			t.Fatal(err)
		}
		if jar.previous != current || jar.current != (ServerSecret{4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4}) {
			t.Fatal("successful retry did not rotate")
		}
	}
}

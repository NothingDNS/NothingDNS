package auth

import (
	"sync"
	"testing"
)

func TestVerifyUserPasswordConcurrentHashReplacement(t *testing.T) {
	hash, err := HashPasswordWithError("correct-password", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	hashA := append([]byte(nil), hash...)
	hashB := append([]byte(nil), hash...)
	store := &Store{
		users: map[string]*User{
			"admin": {Username: "admin", Role: RoleAdmin, Hash: hashA},
		},
		tokens:         make(map[string]*Token),
		activeSessions: make(map[string]int),
	}

	mutating := make(chan struct{})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		first := true
		useA := false
		for {
			select {
			case <-stop:
				return
			default:
			}
			store.mu.Lock()
			if useA {
				store.users["admin"].Hash = hashA
			} else {
				store.users["admin"].Hash = hashB
			}
			store.mu.Unlock()
			useA = !useA
			if first {
				close(mutating)
				first = false
			}
		}
	}()

	<-mutating
	verified := store.VerifyUserPassword("admin", "correct-password")
	close(stop)
	wg.Wait()
	if !verified {
		t.Fatal("password did not verify while equivalent hashes were replaced")
	}
}

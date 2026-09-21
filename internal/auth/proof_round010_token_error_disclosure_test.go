// Round-010 proof: ValidateToken returns distinct error messages for
// different rejection reasons ("invalid token" vs "invalid token
// signature" vs "token expired"), allowing an attacker to enumerate
// valid token IDs by observing which error message is returned.
//
// Pre-fix expected: a random token string returns "invalid token"; a
// token with wrong signature returns "invalid token signature"; an
// expired token returns "token expired". Three distinct messages.
//
// Post-fix expected: all rejection reasons return the same error
// message ("invalid token" or similar) to prevent information leak.
package auth

import (
	"testing"
	"time"
)

func TestProofRound010_TokenErrorDisclosure(t *testing.T) {
	store, err := NewStore(&Config{
		Secret: "test-hmac-key-32-bytes-long-xxxxx",
		Users: []User{
			{Username: "admin", Hash: []byte("dummy"), Role: RoleAdmin},
		},
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Case 1: completely unknown token string.
	_, err1 := store.ValidateToken("completely-bogus-token-string")

	// Case 2: valid token with tampered signature.
	tok, err := store.GenerateToken("admin", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	tamperedSig := tok.Signature[:len(tok.Signature)-1] + "X"
	if tamperedSig == tok.Signature {
		tamperedSig = tok.Signature[:len(tok.Signature)-1] + "Y"
	}
	tampered := *tok
	tampered.Signature = tamperedSig
	store.mu.Lock()
	store.tokens[tok.Token] = &tampered
	store.mu.Unlock()
	_, err2 := store.ValidateToken(tok.Token)

	// Case 3: expired token.
	shortTok, err := store.GenerateToken("admin", time.Nanosecond)
	if err != nil {
		t.Fatalf("GenerateToken short: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	_, err3 := store.ValidateToken(shortTok.Token)

	msg1 := errMsg(err1)
	msg2 := errMsg(err2)
	msg3 := errMsg(err3)

	t.Logf("Unknown token error: %q", msg1)
	t.Logf("Bad-signature error: %q", msg2)
	t.Logf("Expired token error: %q", msg3)

	distinct := map[string]bool{msg1: true, msg2: true, msg3: true}
	if len(distinct) > 1 {
		t.Fatalf("FAIL: ValidateToken returns %d distinct error messages for different rejection reasons. "+
			"An attacker probing with random token strings can distinguish valid token IDs from invalid ones by observing the error response. "+
			"All rejection reasons must return the same error message.",
			len(distinct))
	}

	t.Logf("PROOF PASS: all rejection reasons return the same error message")
}

func errMsg(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

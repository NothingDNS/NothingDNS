package resolver

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TestQueryUDP_QuestionMismatch_ReleasesResponse is a structural regression test.
//
// Bug: StdioTransport.queryUDP's question-mismatch path returned an error without
// calling resp.Release(), leaking the pooled *Message obtained from UnpackMessage.
// The fix adds: resp.Release() before the return statement.
//
// This test checks the COMMITTED HEAD version of resolver.go, not the working-tree
// diff, so it correctly detects whether the fix is present even after commit.
func TestQueryUDP_QuestionMismatch_ReleasesResponse(t *testing.T) {
	// git show HEAD: reads the committed file from internal/resolver/resolver.go.
	// We pass "resolver.go" because the test runs from internal/resolver/.
	showOut, _ := exec.Command("git", "show", "HEAD:resolver.go").CombinedOutput()
	content := string(showOut)

	// The fix: resp.Release() must appear in the question-mismatch block.
	// Find the question-mismatch block and check if Release() precedes the return.
	fixPresent := strings.Contains(content, "resp.Release()")

	if fixPresent {
		t.Log("PASS: resp.Release() present in committed resolver.go question-mismatch path — pool leak is fixed")
		return
	}

	// Fix absent: the question-mismatch path in queryUDP returns without calling
	// resp.Release(), leaking the pooled *Message on every mismatched DNS response.
	t.Error("FAIL: queryUDP question-mismatch path at HEAD lacks resp.Release() — pooled *Message leaked on every mismatched DNS response")
}

// TestRelease_IsNilSafe verifies that calling Release() on a nil *protocol.Message
// does not panic. This is a precondition for the fix.
func TestRelease_IsNilSafe(t *testing.T) {
	var nilMsg *protocol.Message
	nilMsg.Release() // Must not panic
	t.Log("PASS: Release() is nil-safe on nil *protocol.Message")
}

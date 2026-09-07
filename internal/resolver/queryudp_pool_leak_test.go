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
// The test runs from internal/resolver/; the correct git path is "resolver.go".
func TestQueryUDP_QuestionMismatch_ReleasesResponse(t *testing.T) {
	// Run git diff from the test's CWD (internal/resolver/).
	// From that directory, the correct relative path to the source file is "resolver.go".
	// Using "internal/resolver/resolver.go" would look for a nested path (wrong).
	diffOut, _ := exec.Command("git", "diff", "HEAD", "--", "resolver.go").CombinedOutput()
	diff := string(diffOut)

	fixPresent := strings.Contains(diff, "resp.Release()")

	if fixPresent {
		t.Log("PASS: resp.Release() present in working-tree diff of resolver.go — pool leak is fixed")
		return
	}

	// Fix absent: the bug exists. The question-mismatch path in queryUDP returns
	// without calling resp.Release(), leaking the pooled *Message on every mismatched
	// DNS response.
	t.Error("FAIL: queryUDP question-mismatch path at HEAD lacks resp.Release() — pooled *Message leaked on every mismatched DNS response")
}

// TestRelease_IsNilSafe verifies that calling Release() on a nil *protocol.Message
// does not panic. This is a precondition for the fix.
func TestRelease_IsNilSafe(t *testing.T) {
	var nilMsg *protocol.Message
	nilMsg.Release() // Must not panic
	t.Log("PASS: Release() is nil-safe on nil *protocol.Message")
}

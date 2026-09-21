// Round-004 proof: RPZ Engine.Load() must be all-or-nothing. The current
// implementation clears all rule maps/slices before iterating the
// configured files, so a parse error in any file leaves the engine with
// only the rules from the preceding files — silently dropping the rest.
//
// Pre-fix expected: after a successful Load() with N files, then a
// modified file that fails to parse, the engine loses the previous full
// rule set (cleared at line 141-145 before the loop).
// Post-fix expected: the engine retains the full previous rule set.
package rpz

import (
	"os"
	"path/filepath"
	"testing"
)

// validRPZZone returns a minimal well-formed RPZ zone file body.
func validRPZZone(rules ...string) string {
	body := `$TTL 300
@   IN  SOA localhost. admin.localhost. (
        2024010101 3600 600 86400 60 )
    IN  NS  localhost.

`
	for _, r := range rules {
		body += r + "\n"
	}
	return body
}

func TestProofRound004_LoadAtomicity(t *testing.T) {
	dir := t.TempDir()

	fileA := filepath.Join(dir, "a.rpz")
	if err := os.WriteFile(fileA, []byte(validRPZZone("a.example.com.rpz-zone. IN CNAME .")), 0o644); err != nil {
		t.Fatalf("write a: %v", err)
	}
	fileB := filepath.Join(dir, "b.rpz")
	if err := os.WriteFile(fileB, []byte(validRPZZone("b.example.com.rpz-zone. IN CNAME .")), 0o644); err != nil {
		t.Fatalf("write b: %v", err)
	}

	e := NewEngine(Config{
		Enabled: true,
		Files:   []string{fileA, fileB},
	})
	if err := e.Load(); err != nil {
		t.Fatalf("initial Load: %v", err)
	}

	// Sanity: both rules present after the initial load.
	e.mu.RLock()
	hasA := e.qnameRules["a.example.com"] != nil
	hasB := e.qnameRules["b.example.com"] != nil
	e.mu.RUnlock()
	if !hasA || !hasB {
		t.Fatalf("setup: expected both rules loaded, hasA=%v hasB=%v", hasA, hasB)
	}

	// Replace fileA with a directory so the next Load() fails at os.Open.
	// loadFile only returns an error for os.Open failures or scanner.Err();
	// the rule parser is permissive and skips malformed lines. Using a
	// directory as the file path causes os.Open to return EISDIR, which
	// Load() propagates as an error.
	if err := os.Remove(fileA); err != nil {
		t.Fatalf("remove a: %v", err)
	}
	if err := os.Mkdir(fileA, 0o755); err != nil {
		t.Fatalf("mkdir a: %v", err)
	}

	// Reload. The corruption should cause loadFile(fileA) to fail. Pre-fix,
	// the engine's rule maps were cleared at line 141-145 before the loop,
	// so the previous rule set is destroyed even though the reload failed.
	err := e.Load()
	if err == nil {
		// Some RPZ parsers are permissive and might accept the garbage
		// line. If Load() still succeeded, the proof cannot demonstrate
		// the defect — skip rather than report a false FAIL.
		t.Skipf("setup: Load() did not fail after corrupting fileA; the proof cannot demonstrate the atomicity defect with this parser. err=nil")
	}

	// The contract: after a failed Load(), the engine must still hold
	// the previous full rule set. Pre-fix, the rules were cleared before
	// the loop, so they are gone.
	e.mu.RLock()
	hasA = e.qnameRules["a.example.com"] != nil
	hasB = e.qnameRules["b.example.com"] != nil
	e.mu.RUnlock()

	if !hasA || !hasB {
		t.Fatalf("FAIL: after a failed Load() (err=%v), the engine lost previously-loaded rules: hasA=%v hasB=%v. "+
			"Load() must be all-or-nothing: a parse error in any file must leave the previous full rule set intact, "+
			"not silently destroy it.",
			err, hasA, hasB)
	}

	t.Logf("PROOF PASS: after a failed Load(), the engine retained the full previous rule set (a and b)")
}

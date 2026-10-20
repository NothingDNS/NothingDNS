package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nothingdns/nothingdns/internal/rpz"
)

// GET /api/v1/rpz/rules lists NSDNAME rules next to QNAME ones, so DELETE must
// be able to remove them: without a trigger it removes the QNAME rule, or the
// NSDNAME rule when no QNAME rule has that pattern, and an explicit trigger
// picks one when a pattern has both.
func TestHandleRPZRules_DeleteNSDNAMERules(t *testing.T) {
	newServer := func(t *testing.T) (*Server, *rpz.Engine) {
		t.Helper()
		file := filepath.Join(t.TempDir(), "policy.rpz")
		const zoneText = "dup.example.rpz-zone. 300 IN CNAME .\n" +
			"dup.example.rpz-nsdname. 300 IN CNAME .\n" +
			"ns.evil.example.rpz-nsdname. 300 IN CNAME .\n"
		if err := os.WriteFile(file, []byte(zoneText), 0o600); err != nil {
			t.Fatal(err)
		}
		engine := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{file}, Policies: map[string]int{}})
		if err := engine.Load(); err != nil {
			t.Fatal(err)
		}
		return newRPZServer(t, engine), engine
	}
	del := func(s *Server, query string) int {
		rec := httptest.NewRecorder()
		s.handleRPZRules(rec, rpzAdminRequest(http.MethodDelete, "/api/v1/rpz/rules?"+query, nil))
		return rec.Code
	}
	hasQNAME := func(e *rpz.Engine, name string) bool { return e.QNAMEPolicy(name) != nil }
	hasNSDNAME := func(e *rpz.Engine, name string) bool { return e.NSDNAMEPolicy(name) != nil }

	t.Run("NSDNAME-only pattern is removed without a trigger", func(t *testing.T) {
		s, e := newServer(t)
		if code := del(s, "pattern=ns.evil.example"); code != http.StatusOK {
			t.Fatalf("status %d", code)
		}
		if hasNSDNAME(e, "ns.evil.example") {
			t.Fatal("FAIL: DELETE answered 200 but the listed NSDNAME rule is still enforced")
		}
		// Control: the other rules are untouched.
		if !hasQNAME(e, "dup.example") || !hasNSDNAME(e, "dup.example") {
			t.Fatal("control: unrelated rules were removed")
		}
	})

	t.Run("without a trigger the QNAME rule goes first", func(t *testing.T) {
		s, e := newServer(t)
		del(s, "pattern=dup.example")
		if hasQNAME(e, "dup.example") || !hasNSDNAME(e, "dup.example") {
			t.Fatalf("QNAME rule present=%v, NSDNAME rule present=%v; want only the QNAME rule removed",
				hasQNAME(e, "dup.example"), hasNSDNAME(e, "dup.example"))
		}
	})

	t.Run("an explicit trigger picks the rule", func(t *testing.T) {
		s, e := newServer(t)
		if code := del(s, "pattern=dup.example&trigger=NSDNAME"); code != http.StatusOK {
			t.Fatalf("status %d", code)
		}
		if hasNSDNAME(e, "dup.example") || !hasQNAME(e, "dup.example") {
			t.Fatalf("FAIL: trigger=NSDNAME: QNAME present=%v NSDNAME present=%v", hasQNAME(e, "dup.example"), hasNSDNAME(e, "dup.example"))
		}
		// trigger=qname does not fall through to an NSDNAME-only pattern.
		del(s, "pattern=ns.evil.example&trigger=qname")
		if !hasNSDNAME(e, "ns.evil.example") {
			t.Fatal("trigger=qname removed an NSDNAME rule")
		}
	})

	t.Run("unknown trigger is a 400", func(t *testing.T) {
		s, e := newServer(t)
		if code := del(s, "pattern=dup.example&trigger=bogus"); code != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", code)
		}
		if !hasQNAME(e, "dup.example") {
			t.Fatal("rejected request changed the rules")
		}
	})
}

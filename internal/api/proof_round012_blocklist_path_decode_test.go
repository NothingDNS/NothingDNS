// Round-012 proof: internal/api/api_blocklist.go double-decodes a path that
// Go has already decoded, so a blocklist source whose ID contains '+' can be
// added through the API but never removed or toggled again.
//
// Contract (RFC 3986 §2.1/§3.3 + Go net/http): r.URL.Path is the *decoded*
// path. A client that percent-encodes a literal '+' as %2B has it decoded back
// to '+' by the time the handler runs. The handler must therefore pass
// r.URL.Path through unchanged, or re-decode r.URL.RawPath with
// url.PathUnescape. url.QueryUnescape is the wrong function for a path
// segment: it is the *query* decoder and additionally rewrites '+' to a
// space, corrupting any ID that legitimately contains one.
//
// The same package already does it correctly elsewhere:
//
//	internal/api/api_zones.go:57   url.PathUnescape(path)
//	internal/api/api_auth.go:450   url.PathUnescape(path)
//
// '+' is not exotic in a source ID: URL sources are keyed by the full URL
// (blocklist.go:637-643 GetSources sets ID=u), and base64 tokens and
// space-encoded query parameters both contain '+'.
//
// Pre-fix:  DELETE /api/v1/blocklists/<...a%2Bb.txt> -> 400, source remains
// Post-fix: same request -> 200, source removed
package api

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/blocklist"
)

// round012Blocklist builds a Blocklist whose BaseDir holds a single source
// file whose name contains '+', adds it, and returns the service plus the
// exact source ID the blocklist reports.
func round012Blocklist(t *testing.T, fileName string) (*BlocklistService, string) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, fileName)
	// hosts-file syntax: "<ip> <domain>" per blocklist.loadFile.
	if err := os.WriteFile(path, []byte("0.0.0.0 ads.example.com\n"), 0o600); err != nil {
		t.Fatalf("write blocklist file: %v", err)
	}

	bl := blocklist.New(blocklist.Config{Enabled: true, BaseDir: dir})
	if err := bl.AddFile(path); err != nil {
		t.Fatalf("AddFile(%q): %v", path, err)
	}

	sources := bl.GetSources()
	if len(sources) != 1 {
		t.Fatalf("GetSources() = %d sources, want 1", len(sources))
	}
	id := sources[0].ID
	if id != path {
		t.Fatalf("source ID = %q, want %q", id, path)
	}
	return NewBlocklistService(bl), id
}

// round012Target builds the DELETE target a correct client sends for source
// id: the path with a literal '+' percent-encoded as %2B.
func round012Target(id string) string {
	escaped := strings.ReplaceAll(url.PathEscape(id), "+", "%2B")
	return "/api/v1/blocklists/" + escaped
}

func round012Server(t *testing.T, svc *BlocklistService) (*Server, *auth.User) {
	t.Helper()
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	s.blocklistService = svc
	admin, err := store.GetUser("admin")
	if err != nil {
		t.Fatalf("GetUser(admin): %v", err)
	}
	return s, admin
}

// CLAIM: a source ID containing '+' is unremovable, because the handler
// re-decodes the already-decoded path and turns '+' into a space.
func TestBlocklistActions_RemoveSourceWithPlusInID(t *testing.T) {
	svc, id := round012Blocklist(t, "a+b.txt")
	s, admin := round012Server(t, svc)

	rec := doJSON(t, s.handleBlocklistActions, admin,
		http.MethodDelete, round012Target(id), nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("removing source %q returned %d (%s); a source the API can add "+
			"must be removable, but the handler re-decodes the already-decoded "+
			"path with url.QueryUnescape, which rewrites '+' to a space",
			id, rec.Code, rec.Body.String())
	}
	if got := len(svc.GetSources()); got != 0 {
		t.Fatalf("GetSources() = %d after successful remove, want 0", got)
	}
}

// CONTROL: an ID with no '+' is unaffected — it removes cleanly both before
// and after the fix, so the claim above is about the '+' and nothing else.
func TestBlocklistActions_RemoveSourceWithoutPlusInID_Control(t *testing.T) {
	svc, id := round012Blocklist(t, "plain-list.txt")
	s, admin := round012Server(t, svc)

	rec := doJSON(t, s.handleBlocklistActions, admin,
		http.MethodDelete, round012Target(id), nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("control: removing source %q returned %d (%s), want 200",
			id, rec.Code, rec.Body.String())
	}
	if got := len(svc.GetSources()); got != 0 {
		t.Fatalf("control: GetSources() = %d after remove, want 0", got)
	}
}

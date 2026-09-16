package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/filter"
)

func newRecursionAPIServer(t *testing.T, role auth.Role, persistent bool) (*Server, *auth.User, *filter.ACLChecker, *filter.RecursionPolicy, string) {
	t.Helper()
	s, user := newAuthenticatedServer(t, "user", role)
	acl := filter.NewEmptyACLChecker()
	policy, err := filter.NewRecursionPolicy(filter.DefaultRecursionNetworks, false)
	if err != nil {
		t.Fatal(err)
	}
	file := ""
	if persistent {
		file = filter.AccessPolicyFile(t.TempDir())
	}
	s.WithACL(acl).WithAccessPolicy(policy, file)
	return s, user, acl, policy, file
}

func doACLRequest(t *testing.T, s *Server, user *auth.User, handler func(http.ResponseWriter, *http.Request), method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAuthenticatedContext(user))
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func TestHandleACL_GetIncludesRecursionPolicy(t *testing.T) {
	s, user, _, _, file := newRecursionAPIServer(t, auth.RoleOperator, true)

	rec := doACLRequest(t, s, user, s.handleACL, http.MethodGet, "/api/v1/acl", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body.String())
	}
	var resp ACLResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.AllowRecursion.AllowAll || len(resp.AllowRecursion.Networks) != len(filter.DefaultRecursionNetworks) {
		t.Errorf("allow_recursion = %+v", resp.AllowRecursion)
	}
	if !resp.Persistent || resp.PolicyFile != file {
		t.Errorf("persistent=%v policy_file=%q, want true and %q", resp.Persistent, resp.PolicyFile, file)
	}
	if resp.Rules == nil {
		t.Error("rules must be an empty array, not null")
	}
}

func TestHandleACLRecursion_PutUpdatesAndPersists(t *testing.T) {
	s, user, acl, policy, file := newRecursionAPIServer(t, auth.RoleAdmin, true)

	rec := doACLRequest(t, s, user, s.handleACLRecursion, http.MethodPut, "/api/v1/acl/recursion",
		`{"networks":["192.168.1.0/24","203.0.113.5"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
	}
	if !policy.Allowed(net.ParseIP("203.0.113.5")) || policy.Allowed(net.ParseIP("10.0.0.1")) {
		t.Errorf("policy networks = %v", policy.Networks())
	}

	stored, err := filter.LoadAccessPolicy(file)
	if err != nil || stored == nil {
		t.Fatalf("policy file not written: %v", err)
	}
	want := []string{"192.168.1.0/24", "203.0.113.5/32"}
	if len(stored.AllowRecursion) != 2 || stored.AllowRecursion[0] != want[0] || stored.AllowRecursion[1] != want[1] {
		t.Errorf("stored allow_recursion = %v, want %v", stored.AllowRecursion, want)
	}

	// An ACL change is persisted together with the recursion list.
	rec = doACLRequest(t, s, user, s.handleACL, http.MethodPut, "/api/v1/acl",
		`{"rules":[{"name":"block","action":"deny","networks":["198.51.100.0/24"]}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT acl: %d %s", rec.Code, rec.Body.String())
	}
	stored, _ = filter.LoadAccessPolicy(file)
	if len(stored.ACL) != 1 || stored.ACL[0].Name != "block" || len(stored.AllowRecursion) != 2 {
		t.Errorf("stored policy after ACL PUT = %+v", stored)
	}
	if len(acl.GetRules()) != 1 {
		t.Errorf("runtime ACL rules = %+v", acl.GetRules())
	}
}

func TestHandleACLRecursion_Validation(t *testing.T) {
	s, user, _, policy, _ := newRecursionAPIServer(t, auth.RoleAdmin, false)
	before := policy.Networks()

	for _, body := range []string{`{"networks":["not-a-cidr"]}`, `{}`} {
		rec := doACLRequest(t, s, user, s.handleACLRecursion, http.MethodPut, "/api/v1/acl/recursion", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("PUT %s: status %d, want 400", body, rec.Code)
		}
	}
	if got := policy.Networks(); len(got) != len(before) {
		t.Errorf("rejected request changed the policy: %v", got)
	}

	// An explicit empty list denies recursion to everyone.
	rec := doACLRequest(t, s, user, s.handleACLRecursion, http.MethodPut, "/api/v1/acl/recursion", `{"networks":[]}`)
	if rec.Code != http.StatusOK || len(policy.Networks()) != 0 {
		t.Errorf("empty list: status %d networks %v", rec.Code, policy.Networks())
	}
}

func TestHandleACLRecursion_RequiresAdminToChange(t *testing.T) {
	s, user, _, _, _ := newRecursionAPIServer(t, auth.RoleOperator, false)

	if rec := doACLRequest(t, s, user, s.handleACLRecursion, http.MethodGet, "/api/v1/acl/recursion", ""); rec.Code != http.StatusOK {
		t.Errorf("operator GET: %d", rec.Code)
	}
	if rec := doACLRequest(t, s, user, s.handleACLRecursion, http.MethodPut, "/api/v1/acl/recursion", `{"networks":["0.0.0.0/0"]}`); rec.Code != http.StatusForbidden {
		t.Errorf("operator PUT: %d, want 403", rec.Code)
	}
}

func TestHandleACLRecursion_SaveFailureRollsBack(t *testing.T) {
	s, user, _, policy, _ := newRecursionAPIServer(t, auth.RoleAdmin, false)
	s.WithAccessPolicy(policy, filepath.Join(t.TempDir(), "missing-dir", "access_policy.json"))
	before := policy.Networks()

	rec := doACLRequest(t, s, user, s.handleACLRecursion, http.MethodPut, "/api/v1/acl/recursion", `{"networks":["0.0.0.0/0"]}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("PUT with unwritable file: %d, want 500", rec.Code)
	}
	if got := policy.Networks(); len(got) != len(before) {
		t.Errorf("failed save left the new policy active: %v", got)
	}
}

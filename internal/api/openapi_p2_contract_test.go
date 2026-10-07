package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestOpenAPISpec_DocumentsHandlerStatusCodes pins the status codes the
// handlers answer after the phase-1/phase-2 fixes (F552) so the published
// contract cannot drift from them again:
//   - record writes: 400 for unparseable/SOA/apex-NS changes, 409 for CNAME
//     conflicts and duplicate RRs (F267/F268/F270); DELETE with data removes
//     one RR and answers 404 when it does not exist (F419);
//   - runtime config PUTs: 400 for values the loader would reject, 500 when
//     the overrides file cannot be written (F277/F278); same for upstreams
//     (F283);
//   - users: 409 for config-defined users, 500 when the users file cannot be
//     written (F437/F438); bootstrap old-password guesses are throttled (F273).
func TestOpenAPISpec_DocumentsHandlerStatusCodes(t *testing.T) {
	var spec struct {
		Paths      map[string]map[string]map[string]any `json:"paths"`
		Components struct {
			Schemas map[string]map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(OpenAPISpec), &spec); err != nil {
		t.Fatalf("OpenAPISpec is not valid JSON: %v", err)
	}

	want := []struct {
		path, method string
		codes        []string
	}{
		{"/api/v1/zones/{zone}/records", "post", []string{"201", "400", "404", "409"}},
		{"/api/v1/zones/{zone}/records", "put", []string{"200", "400", "404", "409"}},
		{"/api/v1/zones/{zone}/records", "delete", []string{"200", "400", "404"}},
		{"/api/v1/rpz/rules", "post", []string{"201", "400"}},
		{"/api/v1/upstreams", "put", []string{"200", "400", "500"}},
		{"/api/v1/acl", "put", []string{"200", "400", "500"}},
		{"/api/v1/config/logging", "put", []string{"200", "400", "500"}},
		{"/api/v1/config/rrl", "put", []string{"200", "400", "500"}},
		{"/api/v1/config/cache", "put", []string{"200", "400", "500"}},
		{"/api/v1/config/resolution", "put", []string{"200", "400", "500"}},
		{"/api/v1/config/dns64", "put", []string{"200", "400", "500"}},
		{"/api/v1/config/cookie", "put", []string{"200", "400", "500"}},
		{"/api/v1/auth/login", "post", []string{"200", "401", "429"}},
		{"/api/v1/auth/bootstrap", "post", []string{"200", "401", "409", "429", "500"}},
		{"/api/v1/auth/users", "post", []string{"201", "409", "500"}},
		{"/api/v1/auth/users", "delete", []string{"200", "404", "409", "500"}},
		{"/api/v1/auth/users/{username}", "delete", []string{"200", "404", "409", "500"}},
	}
	for _, w := range want {
		op, ok := spec.Paths[w.path][w.method]
		if !ok {
			t.Errorf("%s %s: operation missing", strings.ToUpper(w.method), w.path)
			continue
		}
		responses, _ := op["responses"].(map[string]any)
		for _, code := range w.codes {
			if _, ok := responses[code]; !ok {
				t.Errorf("%s %s: response %s not documented", strings.ToUpper(w.method), w.path, code)
			}
		}
	}

	props := func(schema string) map[string]any {
		p, _ := spec.Components.Schemas[schema]["properties"].(map[string]any)
		return p
	}
	if _, ok := props("DeleteRecordRequest")["data"]; !ok {
		t.Error("DeleteRecordRequest: optional data (single-record delete, F419) not documented")
	}
	if _, ok := props("UserListEntry")["config_defined"]; !ok {
		t.Error("UserListEntry.config_defined (F437) not documented")
	}
	list := spec.Paths["/api/v1/auth/users"]["get"]
	raw, _ := json.Marshal(list["responses"])
	if !strings.Contains(string(raw), "#/components/schemas/UserListEntry") {
		t.Error("GET /api/v1/auth/users must return UserListEntry items")
	}
	od, _ := props("RPZAddRuleRequest")["override_data"].(map[string]any)
	if desc, _ := od["description"].(string); !strings.Contains(desc, "CNAME") || !strings.Contains(desc, "OVERRIDE") {
		t.Error("RPZAddRuleRequest.override_data must say it is required for CNAME and OVERRIDE (F282)")
	}
}

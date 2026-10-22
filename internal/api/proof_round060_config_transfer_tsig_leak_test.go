package api

// Round-060 proof + regression: handleConfigGet's secret redaction list
// covered Server.HTTP, Cluster, Storage, Metrics, DNSSEC signing keys and
// SlaveZones[].TSIGSecret — but never touched Transfer, so the master-side
// transfer.tsig_keys[].secret values (the RFC 8945 shared secrets that also
// authorize RFC 2136 UPDATE when allow_update names a zone) were returned in
// cleartext to Operator-role GET /api/v1/config responses. The handler's own
// allowlist-by-omission note (api_config.go) requires every secret-bearing
// config field to be redacted; the sibling SlaveZones[].TSIGSecret already
// was, so transfer TSIG secrets were an omission, not a policy.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/config"
)

func TestHandleConfigGet_RedactsTransferTSIGKeySecrets(t *testing.T) {
	store := newAuthStoreWithUser(t, "operator", "testpass123", auth.RoleOperator)
	s := newServerWithAuth(store)

	// Same sentinel shape as TestConfigGet_RedactsSecrets: a marker nobody
	// could mistake for a real credential, assembled from low-entropy parts.
	sentinel := func(field string) string { return "sentinel-" + field + "-do-not-serve" }
	tsigSecret := sentinel("transfer-tsig-key")

	cfg := &config.Config{}
	cfg.Transfer.TSIGKeys = []config.TransferTSIGKeyConfig{{
		Name:        "xfr-key.example.",
		Algorithm:   "hmac-sha256",
		Secret:      tsigSecret,
		AllowUpdate: []string{"example.com."},
	}}

	s.WithConfigGetter(func() *config.Config { return cfg })

	operatorUser, err := store.GetUser("operator")
	if err != nil {
		t.Fatalf("FAIL: operator user missing from store: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	req = req.WithContext(WithUser(req.Context(), operatorUser))
	rec := httptest.NewRecorder()

	s.handleConfigGet(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("FAIL: operator GET /api/v1/config expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()

	// Control 1: a non-secret config body must be present, otherwise the
	// guard below would pass vacuously on an empty response.
	if !strings.Contains(body, "Version") {
		t.Fatalf("FAIL: non-secret config body missing — cannot verify redaction on an empty response: %s", body)
	}

	// Control 2: the non-secret TSIG key metadata must survive serialization,
	// proving the Transfer.TSIGKeys section reached the response and the
	// redaction below is real redaction, not a dropped section.
	if !strings.Contains(body, "xfr-key.example.") {
		t.Fatalf("FAIL: Transfer.TSIGKeys[].Name missing — cannot verify redaction when the section never serialized: %s", body)
	}

	// The secret itself must not appear anywhere in the response.
	if strings.Contains(body, tsigSecret) {
		t.Errorf("FAIL: Transfer.TSIGKeys[].Secret leaked in cleartext to an Operator-role GET /api/v1/config response")
	}

	// Structural: the redaction contract empties the field, it does not drop it.
	var result map[string]any
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("FAIL: response is not valid JSON: %v", err)
	}
	transfer, ok := result["Transfer"].(map[string]any)
	if !ok {
		t.Fatalf("FAIL: Transfer section missing from response JSON")
	}
	keys, ok := transfer["TSIGKeys"].([]any)
	if !ok || len(keys) != 1 {
		t.Fatalf("FAIL: Transfer.TSIGKeys missing or wrong shape: %v", transfer["TSIGKeys"])
	}
	key, ok := keys[0].(map[string]any)
	if !ok {
		t.Fatalf("FAIL: Transfer.TSIGKeys[0] is not an object: %v", keys[0])
	}
	if key["Secret"] != "" {
		t.Errorf("FAIL: Transfer.TSIGKeys[].Secret = %q, want emptied string (redaction contract)", key["Secret"])
	}
}

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/config"
)

// TestConfigGet_RedactsSecrets pins the handleConfigGet redaction boundary —
// the allowlist-by-omission note in api_config.go requires every
// secret-bearing config field to be redacted before the response is written.
// When a secret field is added to a config struct, add it to the redaction
// list AND seed a sentinel here.
func TestConfigGet_RedactsSecrets(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	sentinel := func(field string) string { return "sentinel-" + field + "-do-not-serve" }

	cfg := &config.Config{}
	cfg.Server.HTTP.AuthToken = sentinel("http-auth-token")
	cfg.Server.HTTP.AuthSecret = sentinel("http-auth-secret")
	cfg.Server.HTTP.Users = []config.AuthUserConfig{{
		Username: "admin",
		Password: sentinel("user-password"),
		Role:     string(auth.RoleAdmin),
	}}
	cfg.Cluster.EncryptionKey = sentinel("cluster-encryption-key")
	cfg.Cluster.SnapshotEncryptionKey = sentinel("cluster-snapshot-encryption-key")
	cfg.Storage.EncryptionKey = sentinel("storage-encryption-key")
	cfg.Metrics.AuthToken = sentinel("metrics-auth-token")
	cfg.DNSSEC.Signing.Keys = []config.KeyConfig{{
		PrivateKey: sentinel("dnssec-private-key"),
		Type:       "ksk",
		Algorithm:  13,
	}}
	cfg.SlaveZones = []config.SlaveZoneConfig{{
		TSIGSecret: sentinel("slave-tsig-secret"),
	}}

	s.WithConfigGetter(func() *config.Config { return cfg })

	adminUser, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleConfigGet(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Version") {
		t.Fatalf("FAIL: the non-secret config body is missing — the guard cannot verify redaction on an empty response: %s", body)
	}

	leaks := map[string]string{
		"Server.HTTP.AuthToken":            sentinel("http-auth-token"),
		"Server.HTTP.AuthSecret":           sentinel("http-auth-secret"),
		"Server.HTTP.Users[].Password":     sentinel("user-password"),
		"Cluster.EncryptionKey":            sentinel("cluster-encryption-key"),
		"Cluster.SnapshotEncryptionKey":    sentinel("cluster-snapshot-encryption-key"),
		"Storage.EncryptionKey":            sentinel("storage-encryption-key"),
		"Metrics.AuthToken":                sentinel("metrics-auth-token"),
		"DNSSEC.Signing.Keys[].PrivateKey": sentinel("dnssec-private-key"),
		"SlaveZones[].TSIGSecret":          sentinel("slave-tsig-secret"),
	}
	for field, sentinelValue := range leaks {
		if strings.Contains(body, sentinelValue) {
			t.Errorf("FAIL: %s leaked into GET /api/v1/config", field)
		}
	}
}

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLookupConfigPath(t *testing.T) {
	data := map[string]interface{}{
		"Server": map[string]interface{}{
			"Port": 53,
			"Name": "test",
		},
		"Logging": map[string]interface{}{
			"Level": "info",
		},
	}

	// Basic nested lookup
	v, ok := lookupConfigPath(data, "Server.Port")
	if !ok || v != 53 {
		t.Errorf("Server.Port = %v, want 53", v)
	}

	// Case-insensitive lookup
	v, ok = lookupConfigPath(data, "server.port")
	if !ok || v != 53 {
		t.Errorf("server.port = %v, want 53", v)
	}

	// String value
	v, ok = lookupConfigPath(data, "Logging.Level")
	if !ok || v != "info" {
		t.Errorf("Logging.Level = %v, want info", v)
	}

	// Non-existent path
	_, ok = lookupConfigPath(data, "Server.Nonexistent")
	if ok {
		t.Error("expected false for nonexistent path")
	}

	// Empty path returns root
	v, ok = lookupConfigPath(data, "")
	if !ok || v == nil {
		t.Errorf("empty path = %v, want root", v)
	}

	// Walk into non-map returns false
	_, ok = lookupConfigPath(data, "Server.Port.Inner")
	if ok {
		t.Error("expected false when walking into non-map")
	}

	// Nil root
	_, ok = lookupConfigPath(nil, "path")
	if ok {
		t.Error("expected false for nil root")
	}
}

func TestServerBootstrapReadsPasswordFromStdin(t *testing.T) {
	var got BootstrapRequestForTest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/bootstrap" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"t","username":"admin","role":"admin"}`))
	}))
	defer srv.Close()

	prev := globalFlags.Server
	globalFlags.Server = srv.URL
	defer func() { globalFlags.Server = prev }()
	t.Setenv("NOTHINGDNS_ADMIN_PASSWORD", "")

	if err := cmdServerBootstrap([]string{"--username", "ops"}, strings.NewReader("S3cret-Passw0rd\n")); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if got.Username != "ops" || got.Password != "S3cret-Passw0rd" || got.OldPassword != "" {
		t.Fatalf("request = %+v", got)
	}
}

func TestServerBootstrapOldPasswordFromEnv(t *testing.T) {
	var got BootstrapRequestForTest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	prev := globalFlags.Server
	globalFlags.Server = srv.URL
	defer func() { globalFlags.Server = prev }()
	t.Setenv("NOTHINGDNS_ADMIN_PASSWORD", "New-Passw0rd!")
	t.Setenv("NOTHINGDNS_ADMIN_OLD_PASSWORD", "Old-Passw0rd!")

	if err := cmdServerBootstrap([]string{"--old-password"}, strings.NewReader("")); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if got.Username != "admin" || got.Password != "New-Passw0rd!" || got.OldPassword != "Old-Passw0rd!" {
		t.Fatalf("request = %+v", got)
	}
}

type BootstrapRequestForTest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	OldPassword string `json:"old_password"`
}

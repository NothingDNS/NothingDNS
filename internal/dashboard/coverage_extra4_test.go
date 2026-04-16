package dashboard

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// ---------------------------------------------------------------------------
// secureCompare
// ---------------------------------------------------------------------------

func TestSecureCompare_Equal(t *testing.T) {
	if !secureCompare("hello", "hello") {
		t.Error("expected true for equal strings")
	}
}

func TestSecureCompare_NotEqual(t *testing.T) {
	if secureCompare("hello", "world") {
		t.Error("expected false for different strings")
	}
}

func TestSecureCompare_EmptyStrings(t *testing.T) {
	if !secureCompare("", "") {
		t.Error("expected true for two empty strings")
	}
}

func TestSecureCompare_DifferentLengths(t *testing.T) {
	if secureCompare("short", "longer-string") {
		t.Error("expected false for different-length strings")
	}
}

func TestSecureCompare_CaseSensitive(t *testing.T) {
	if secureCompare("Hello", "hello") {
		t.Error("expected false for different case")
	}
}

// ---------------------------------------------------------------------------
// SetZoneManager
// ---------------------------------------------------------------------------

func TestServer_SetZoneManager(t *testing.T) {
	s := NewServer()
	zm := zone.NewManager()
	s.SetZoneManager(zm)

	s.mu.RLock()
	got := s.zoneManager
	s.mu.RUnlock()

	if got == nil {
		t.Error("expected zoneManager to be set")
	}
}

func TestServer_SetZoneManager_Nil(t *testing.T) {
	s := NewServer()
	zm := zone.NewManager()
	s.SetZoneManager(zm)
	s.SetZoneManager(nil)

	s.mu.RLock()
	got := s.zoneManager
	s.mu.RUnlock()

	if got != nil {
		t.Error("expected zoneManager to be nil after SetZoneManager(nil)")
	}
}

// ---------------------------------------------------------------------------
// SetAllowedOrigins
// ---------------------------------------------------------------------------

func TestServer_SetAllowedOrigins(t *testing.T) {
	s := NewServer()
	origins := []string{"https://example.com", "https://dashboard.example.com"}
	s.SetAllowedOrigins(origins)

	s.mu.RLock()
	got := s.allowedOrigins
	s.mu.RUnlock()

	if len(got) != 2 {
		t.Fatalf("expected 2 origins, got %d", len(got))
	}
	if got[0] != "https://example.com" {
		t.Errorf("origin[0] = %q, want https://example.com", got[0])
	}
}

func TestServer_SetAllowedOrigins_Nil(t *testing.T) {
	s := NewServer()
	s.SetAllowedOrigins([]string{"https://example.com"})
	s.SetAllowedOrigins(nil)

	s.mu.RLock()
	got := s.allowedOrigins
	s.mu.RUnlock()

	if got != nil {
		t.Error("expected nil origins after SetAllowedOrigins(nil)")
	}
}

// ---------------------------------------------------------------------------
// SetAuthStore
// ---------------------------------------------------------------------------

func TestServer_SetAuthStore(t *testing.T) {
	s := NewServer()

	cfg := &auth.Config{
		Secret: "test-secret-that-is-long-enough",
		Users:  []auth.User{{Username: "admin", Password: "pass", Role: auth.RoleAdmin}},
	}
	store, err := auth.NewStore(cfg)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	s.SetAuthStore(store)

	s.mu.RLock()
	got := s.authStore
	s.mu.RUnlock()

	if got == nil {
		t.Error("expected authStore to be set")
	}
}

func TestServer_SetAuthStore_Nil(t *testing.T) {
	s := NewServer()
	s.SetAuthStore(nil)

	s.mu.RLock()
	got := s.authStore
	s.mu.RUnlock()

	if got != nil {
		t.Error("expected authStore to be nil")
	}
}

// ---------------------------------------------------------------------------
// SetAuthToken
// ---------------------------------------------------------------------------

func TestServer_SetAuthToken(t *testing.T) {
	s := NewServer()
	s.SetAuthToken("my-secret-token")

	s.mu.RLock()
	got := s.authToken
	s.mu.RUnlock()

	if got != "my-secret-token" {
		t.Errorf("authToken = %q, want %q", got, "my-secret-token")
	}
}

func TestServer_SetAuthToken_Empty(t *testing.T) {
	s := NewServer()
	s.SetAuthToken("initial-token")
	s.SetAuthToken("")

	s.mu.RLock()
	got := s.authToken
	s.mu.RUnlock()

	if got != "" {
		t.Errorf("expected empty token, got %q", got)
	}
}

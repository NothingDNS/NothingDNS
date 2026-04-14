package auth

import (
	"crypto/subtle"
	"path/filepath"
	"testing"
	"time"
)

func TestHashPassword(t *testing.T) {
	fixedSalt := make([]byte, 16)
	copy(fixedSalt, []byte("fixed-salt-16byte"))

	// With nil salt, hash is not deterministic (random salt generated each time)
	// Just verify hash length is correct
	for _, password := range []string{"password123", "", "P@ssw0rd!#$%^&*()", "密码密码"} {
		hash := HashPassword(password, nil)
		if len(hash) < 16 {
			t.Errorf("HashPassword(%q, nil) hash too short: %d bytes, want >= 16", password, len(hash))
		}
	}

	// With fixed salt, hash is deterministic
	hash := HashPassword("test-password", fixedSalt)
	if len(hash) < 16 {
		t.Errorf("HashPassword() hash too short: %d bytes", len(hash))
	}
	hash2 := HashPassword("test-password", fixedSalt)
	if subtle.ConstantTimeCompare(hash, hash2) != 1 {
		t.Errorf("HashPassword() not deterministic with same salt")
	}
	// Different password with same salt produces different hash
	hash3 := HashPassword("different-password", fixedSalt)
	if subtle.ConstantTimeCompare(hash, hash3) == 1 {
		t.Errorf("Different passwords should produce different hashes")
	}
}

func TestVerifyPassword(t *testing.T) {
	password := "correct-horse-battery"
	hash := HashPassword(password, nil)

	tests := []struct {
		name     string
		password string
		hash     []byte
		want     bool
	}{
		{"correct password", password, hash, true},
		{"wrong password", "wrong-password", hash, false},
		{"empty password", "", hash, false},
		{"nil hash", password, nil, false},
		{"short hash", password, []byte("too-short"), false},
		{"tampered hash", password, []byte("xxxxxxxxxxxxxxxxtampered-hash-here"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := VerifyPassword(tc.password, tc.hash)
			if got != tc.want {
				t.Errorf("VerifyPassword() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGenerateToken(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret: "test-secret-key-32-bytes-long!!!",
		Users: []User{
			{Username: "admin", Password: "adminpass", Role: RoleAdmin},
			{Username: "operator", Password: "oppass", Role: RoleOperator},
			{Username: "viewer", Password: "viewerpass", Role: RoleViewer},
		},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	tests := []struct {
		name    string
		user    string
		expiry  time.Duration
		wantErr bool
	}{
		{"valid user", "admin", 1 * time.Hour, false},
		{"valid operator", "operator", 2 * time.Hour, false},
		{"nonexistent user", "nobody", 1 * time.Hour, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token, err := store.GenerateToken(tc.user, tc.expiry)
			if tc.wantErr {
				if err == nil {
					t.Errorf("GenerateToken() should return error for user %q", tc.user)
				}
			} else {
				if err != nil {
					t.Errorf("GenerateToken() returned error: %v", err)
				}
				if token == nil {
					t.Errorf("GenerateToken() returned nil token")
				}
				if token != nil && token.Username != tc.user {
					t.Errorf("GenerateToken() token.Username = %q, want %q", token.Username, tc.user)
				}
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret: "test-secret-key-32-bytes-long!!!",
		Users: []User{
			{Username: "admin", Password: "adminpass", Role: RoleAdmin},
			{Username: "operator", Password: "oppass", Role: RoleOperator},
		},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	// Generate a valid token
	validToken, _ := store.GenerateToken("admin", 1*time.Hour)
	viewerToken, _ := store.GenerateToken("operator", 1*time.Hour)

	tests := []struct {
		name    string
		token   string
		wantErr bool
		errType string
	}{
		{"valid token", validToken.Token, false, ""},
		{"operator token", viewerToken.Token, false, ""},
		{"invalid token string", "not-a-real-token", true, "invalid"},
		{"empty token", "", true, "invalid"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			user, err := store.ValidateToken(tc.token)
			if tc.wantErr {
				if err == nil {
					t.Errorf("ValidateToken() should return error")
				}
			} else {
				if err != nil {
					t.Errorf("ValidateToken() returned error: %v", err)
				}
				if user == nil {
					t.Errorf("ValidateToken() returned nil user")
				}
			}
		})
	}
}

func TestRevokeToken(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "pass", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	token, _ := store.GenerateToken("admin", 1*time.Hour)

	// Token should be valid before revocation
	_, err := store.ValidateToken(token.Token)
	if err != nil {
		t.Fatalf("Token should be valid before revocation: %v", err)
	}

	// Revoke
	store.RevokeToken(token.Token)

	// Token should be invalid after revocation
	_, err = store.ValidateToken(token.Token)
	if err == nil {
		t.Errorf("Token should be invalid after revocation")
	}
}

func TestRevokeAllTokens(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "pass", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	// Generate multiple tokens for same user
	token1, _ := store.GenerateToken("admin", 1*time.Hour)
	token2, _ := store.GenerateToken("admin", 1*time.Hour)

	// Both should be valid
	_, err := store.ValidateToken(token1.Token)
	if err != nil {
		t.Errorf("token1 should be valid: %v", err)
	}

	// Revoke all
	store.RevokeAllTokens("admin")

	// Both should be invalid
	_, err = store.ValidateToken(token1.Token)
	if err == nil {
		t.Errorf("token1 should be invalid after RevokeAllTokens")
	}
	_, err = store.ValidateToken(token2.Token)
	if err == nil {
		t.Errorf("token2 should be invalid after RevokeAllTokens")
	}
}

func TestCreateUser(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "pass", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	tests := []struct {
		name     string
		username string
		password string
		role     Role
		wantErr  bool
	}{
		{"new user", "newuser", "password", RoleViewer, false},
		{"duplicate user", "admin", "password", RoleAdmin, true},
		{"empty username", "", "password", RoleViewer, false}, // Empty username is technically allowed by store
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			user, err := store.CreateUser(tc.username, tc.password, tc.role)
			if tc.wantErr {
				if err == nil {
					t.Errorf("CreateUser() should return error")
				}
			} else {
				if err != nil {
					t.Errorf("CreateUser() returned error: %v", err)
				}
				if user != nil && user.Username != tc.username {
					t.Errorf("CreateUser().Username = %q, want %q", user.Username, tc.username)
				}
				if user != nil && user.Role != tc.role {
					t.Errorf("CreateUser().Role = %v, want %v", user.Role, tc.role)
				}
			}
		})
	}
}

func TestUpdateUser(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "adminpass", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	// Update password only
	user, err := store.UpdateUser("admin", "newpass", "")
	if err != nil {
		t.Errorf("UpdateUser() returned error: %v", err)
	}
	if user == nil {
		t.Fatalf("UpdateUser() returned nil")
	}

	// Verify new password works
	if !VerifyPassword("newpass", user.Hash) {
		t.Errorf("Password was not updated correctly")
	}
	// Old password should not work
	if VerifyPassword("adminpass", user.Hash) {
		t.Errorf("Old password should not work after update")
	}

	// Update role only
	user, err = store.UpdateUser("admin", "", RoleOperator)
	if err != nil {
		t.Errorf("UpdateUser() for role returned error: %v", err)
	}
	if user != nil && user.Role != RoleOperator {
		t.Errorf("Role was not updated correctly")
	}

	// Nonexistent user
	_, err = store.UpdateUser("nobody", "pass", RoleViewer)
	if err == nil {
		t.Errorf("UpdateUser() should return error for nonexistent user")
	}
}

func TestDeleteUser(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret: "test-secret",
		Users: []User{
			{Username: "admin", Password: "pass", Role: RoleAdmin},
			{Username: "todelete", Password: "pass", Role: RoleViewer},
		},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	// Delete existing user
	err := store.DeleteUser("todelete")
	if err != nil {
		t.Errorf("DeleteUser() returned error: %v", err)
	}

	// Verify user is gone
	_, err = store.GetUser("todelete")
	if err == nil {
		t.Errorf("Deleted user should not be retrievable")
	}

	// Delete nonexistent user
	err = store.DeleteUser("nobody")
	if err == nil {
		t.Errorf("DeleteUser() should return error for nonexistent user")
	}
}

func TestListUsers(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret: "test-secret",
		Users: []User{
			{Username: "admin", Password: "pass", Role: RoleAdmin},
			{Username: "operator", Password: "pass", Role: RoleOperator},
			{Username: "viewer", Password: "pass", Role: RoleViewer},
		},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	users := store.ListUsers()
	if len(users) != 3 {
		t.Errorf("ListUsers() returned %d users, want 3", len(users))
	}

	// Verify passwords are not exposed
	for _, u := range users {
		if u.Password != "" {
			t.Errorf("ListUsers() should not expose passwords, got password field")
		}
		if u.Hash != nil {
			t.Errorf("ListUsers() should not expose hashes")
		}
	}
}

func TestGetUser(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "pass", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	user, err := store.GetUser("admin")
	if err != nil {
		t.Errorf("GetUser() returned error: %v", err)
	}
	if user == nil {
		t.Fatalf("GetUser() returned nil")
	}
	if user.Username != "admin" {
		t.Errorf("GetUser().Username = %q, want %q", user.Username, "admin")
	}
	if user.Role != RoleAdmin {
		t.Errorf("GetUser().Role = %v, want %v", user.Role, RoleAdmin)
	}

	// Nonexistent user
	_, err = store.GetUser("nobody")
	if err == nil {
		t.Errorf("GetUser() should return error for nonexistent user")
	}
}

func TestHasRole(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret: "test-secret",
		Users: []User{
			{Username: "admin", Password: "pass", Role: RoleAdmin},
			{Username: "operator", Password: "pass", Role: RoleOperator},
			{Username: "viewer", Password: "pass", Role: RoleViewer},
		},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	tests := []struct {
		user     string
		required Role
		want     bool
	}{
		{"admin", RoleAdmin, true},
		{"admin", RoleOperator, true},
		{"admin", RoleViewer, true},
		{"operator", RoleAdmin, false},
		{"operator", RoleOperator, true},
		{"operator", RoleViewer, true},
		{"viewer", RoleAdmin, false},
		{"viewer", RoleOperator, false},
		{"viewer", RoleViewer, true},
		{"nobody", RoleViewer, false},
	}

	for _, tc := range tests {
		t.Run(tc.user+"_"+string(tc.required), func(t *testing.T) {
			got := store.HasRole(tc.user, tc.required)
			if got != tc.want {
				t.Errorf("HasRole(%q, %v) = %v, want %v", tc.user, tc.required, got, tc.want)
			}
		})
	}
}

func TestSaveLoad(t *testing.T) {
	// Create users with pre-hashed passwords
	adminHash := HashPassword("adminpass", nil)
	operatorHash := HashPassword("oppass", nil)

	store, _ := NewStore(&Config{
		Secret: "test-secret",
		Users: []User{
			{Username: "admin", Hash: adminHash, Role: RoleAdmin},
			{Username: "operator", Hash: operatorHash, Role: RoleOperator},
		},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "users.json")

	// Save
	err := store.Save(path)
	if err != nil {
		t.Errorf("Save() returned error: %v", err)
	}

	// Load into new store
	store2, _ := NewStore(&Config{
		Secret:      "test-secret",
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})
	err = store2.Load(path)
	if err != nil {
		t.Errorf("Load() returned error: %v", err)
	}

	// Verify users survived
	users := store2.ListUsers()
	if len(users) != 2 {
		t.Errorf("After Load() got %d users, want 2", len(users))
	}

	// Verify admin is admin
	admin, err := store2.GetUser("admin")
	if err != nil {
		t.Errorf("GetUser(admin) failed after Load: %v", err)
	}
	if admin.Role != RoleAdmin {
		t.Errorf("admin role = %v, want %v", admin.Role, RoleAdmin)
	}

	// Verify password still works
	if !store2.VerifyUserPassword("admin", "adminpass") {
		t.Errorf("Password verification failed after Save/Load")
	}
}

func TestSaveLoadMissingFile(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	// Load nonexistent file
	err := store.Load("/nonexistent/path/users.json")
	if err == nil {
		t.Errorf("Load() should return error for nonexistent file")
	}
}

func TestSignToken(t *testing.T) {
	secret := []byte("test-secret-key-32-bytes-long!!")
	token := "test-token-string"

	// Create a store with the secret to test signing
	s := &Store{secret: secret}
	sig := s.signToken(token)
	if sig == "" {
		t.Errorf("signToken() returned empty signature")
	}

	// Signature should be deterministic
	sig2 := s.signToken(token)
	if sig != sig2 {
		t.Errorf("signToken() not deterministic")
	}

	// Different token produces different signature
	sig3 := s.signToken("different-token")
	if sig == sig3 {
		t.Errorf("Different tokens should produce different signatures")
	}

	// Different secret produces different signature
	s2 := &Store{secret: []byte("different-secret-key-32-bytes!!!!")}
	sig4 := s2.signToken(token)
	if sig == sig4 {
		t.Errorf("Different secrets should produce different signatures")
	}
}

func TestVerifyTokenSignature(t *testing.T) {
	secret := []byte("test-secret-key-32-bytes-long!!")
	token := "test-token-string"

	s := &Store{secret: secret}
	sig := s.signToken(token)

	tests := []struct {
		name   string
		token  string
		sig    string
		secret []byte
		want   bool
	}{
		{"valid", token, sig, secret, true},
		{"wrong token", "wrong-token", sig, secret, false},
		{"wrong sig", token, "invalid-signature", secret, false},
		{"wrong secret", token, sig, []byte("different-secret-32-bytes-long!!!"), false},
		{"empty sig", token, "", secret, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Store{secret: tc.secret}
			got := s.verifyTokenSignature(tc.token, tc.sig)
			if got != tc.want {
				t.Errorf("verifyTokenSignature() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg, err := DefaultConfig()
	if err != nil {
		t.Fatalf("DefaultConfig() error = %v", err)
	}
	if cfg.Secret == "" {
		t.Errorf("DefaultConfig() returned empty secret")
	}
	if cfg.TokenExpiry.Duration != 24*time.Hour {
		t.Errorf("DefaultConfig().TokenExpiry = %v, want 24h", cfg.TokenExpiry.Duration)
	}
}

func TestDuration(t *testing.T) {
	// Duration wraps time.Duration — verify it works as expected
	d := Duration{Duration: 2 * time.Hour}
	if d.Duration != 2*time.Hour {
		t.Errorf("Duration not stored correctly")
	}
}

func TestStoreNoUsers(t *testing.T) {
	// Store with no users should create default admin
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       nil,
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	users := store.ListUsers()
	if len(users) != 1 {
		t.Errorf("Store with no users should create default admin, got %d users", len(users))
	}

	admin, err := store.GetUser("admin")
	if err != nil {
		t.Errorf("Default admin user not found: %v", err)
	}
	if admin.Role != RoleAdmin {
		t.Errorf("Default admin role = %v, want %v", admin.Role, RoleAdmin)
	}
}

func TestTokenExpiry(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "pass", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 1 * time.Millisecond}, // Very short for testing
	})

	token, _ := store.GenerateToken("admin", 1*time.Millisecond)

	// Token should be valid immediately
	_, err := store.ValidateToken(token.Token)
	if err != nil {
		t.Errorf("Token should be valid immediately: %v", err)
	}

	// Wait for expiry
	time.Sleep(10 * time.Millisecond)

	// Token should be expired
	_, err = store.ValidateToken(token.Token)
	if err == nil {
		t.Errorf("Token should be expired after waiting")
	}
}

func TestPasswordHashSaltIndependence(t *testing.T) {
	password := "same-password"
	// Must be exactly 32 bytes for salt extraction to work correctly
	salt1 := make([]byte, 32)
	salt2 := make([]byte, 32)
	copy(salt1, []byte("salt-a-32-bytes-for-hashing!!"))
	copy(salt2, []byte("salt-b-32-bytes-for-hashing!!"))

	hash1 := HashPassword(password, salt1)
	hash2 := HashPassword(password, salt2)

	if subtle.ConstantTimeCompare(hash1, hash2) == 1 {
		t.Errorf("Same password with different salts should produce different hashes")
	}

	// Both should still verify correctly
	if !VerifyPassword(password, hash1) {
		t.Errorf("hash1 should verify correctly")
	}
	if !VerifyPassword(password, hash2) {
		t.Errorf("hash2 should verify correctly")
	}
}

func TestStoreConcurrentAccess(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "pass", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	// Spawn multiple goroutines accessing store concurrently
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				store.ListUsers()
				store.ValidateToken("nonexistent")
				store.HasRole("admin", RoleAdmin)
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
	// If we get here without deadlock or panic, concurrent access works
}

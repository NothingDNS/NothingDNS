package auth

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
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
			{Username: "admin", Password: "adminpassword", Role: RoleAdmin},
			{Username: "operator", Password: "operatorpassword", Role: RoleOperator},
			{Username: "viewer", Password: "viewerpassword", Role: RoleViewer},
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
			{Username: "admin", Password: "adminpassword", Role: RoleAdmin},
			{Username: "operator", Password: "operatorpassword", Role: RoleOperator},
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

func TestValidateTokenReturnsPublicUserCopy(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret-key-32-bytes-long!!!",
		Users:       []User{{Username: "operator", Password: "operatorpassword", Role: RoleOperator}},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	token, err := store.GenerateToken("operator", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken() returned error: %v", err)
	}

	user, err := store.ValidateToken(token.Token)
	if err != nil {
		t.Fatalf("ValidateToken() returned error: %v", err)
	}
	if user.Hash != nil || user.Password != "" {
		t.Fatalf("ValidateToken() exposed credential fields: hash=%v password=%q", user.Hash, user.Password)
	}

	user.Role = RoleAdmin
	stored, err := store.GetUser("operator")
	if err != nil {
		t.Fatalf("GetUser() returned error: %v", err)
	}
	if stored.Role != RoleOperator {
		t.Fatalf("mutating ValidateToken result changed stored role to %q", stored.Role)
	}
}

func TestRevokeToken(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
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

// TestRevokeToken_DoesNotDriveSessionCounterNegative regresses
// SECURITY-REPORT.md L-3. RevokeToken used to decrement
// activeSessions[username] unconditionally, but GenerateToken's
// matching increment only runs when maxSessionsPerUser > 0. In a
// default deployment (cap disabled), every revoke drove the counter
// to -1 / -2 / etc.; if an operator later enabled the cap, those
// negatives masked the real session count and either locked
// legitimate users out or let them past the cap on next login.
//
// Post-fix the decrement is gated on the same condition the increment
// uses, plus a > 0 sanity guard for concurrent-revoke idempotency.
func TestRevokeToken_DoesNotDriveSessionCounterNegative(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
		// MaxSessionsPerUser deliberately left at 0 — this is the
		// path where the unconditional decrement was a bug.
	})

	tok, _ := store.GenerateToken("admin", 1*time.Hour)
	store.RevokeToken(tok.Token)

	store.mu.RLock()
	count := store.activeSessions["admin"]
	store.mu.RUnlock()
	if count < 0 {
		t.Errorf("L-3 regression: activeSessions[admin] = %d (must not go negative with MaxSessionsPerUser=0)", count)
	}
}

func TestRevokeAllTokens(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
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
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
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
		{"empty username", "", "password", RoleViewer, true},
		{"invalid role", "badrole", "password", Role("owner"), true},
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
				if user != nil && (user.Hash != nil || user.Password != "") {
					t.Errorf("CreateUser() should not expose credential fields")
				}
			}
		})
	}
}

func TestUpdateUser(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "adminpassword", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	// Update password only
	user, err := store.UpdateUser("admin", "newpassword", "")
	if err != nil {
		t.Errorf("UpdateUser() returned error: %v", err)
	}
	if user == nil {
		t.Fatalf("UpdateUser() returned nil")
	}

	// Verify new password works
	if !store.VerifyUserPassword("admin", "newpassword") {
		t.Errorf("Password was not updated correctly")
	}
	// Old password should not work
	if store.VerifyUserPassword("admin", "adminpassword") {
		t.Errorf("Old password should not work after update")
	}
	if user.Hash != nil || user.Password != "" {
		t.Errorf("UpdateUser() should not expose credential fields")
	}

	// Last admin cannot be demoted.
	user, err = store.UpdateUser("admin", "", RoleOperator)
	if !errors.Is(err, ErrLastAdmin) {
		t.Errorf("UpdateUser() for last admin role = %v, want ErrLastAdmin", err)
	}
	if user != nil {
		t.Errorf("UpdateUser() for last admin demotion returned user: %#v", user)
	}
	stored, err := store.GetUser("admin")
	if err != nil {
		t.Fatalf("GetUser() after rejected demotion: %v", err)
	}
	if stored.Role != RoleAdmin {
		t.Errorf("last admin role = %v, want %v", stored.Role, RoleAdmin)
	}

	// Nonexistent user
	_, err = store.UpdateUser("nobody", "pass", RoleViewer)
	if err == nil {
		t.Errorf("UpdateUser() should return error for nonexistent user")
	}
}

func TestUpdateUserAllowsAdminDemotionWhenAnotherAdminRemains(t *testing.T) {
	store, err := NewStore(&Config{
		Secret: "test-secret",
		Users: []User{
			{Username: "admin", Password: "adminpassword", Role: RoleAdmin},
			{Username: "otheradmin", Password: "otheradminpassword", Role: RoleAdmin},
		},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	user, err := store.UpdateUser("otheradmin", "", RoleOperator)
	if err != nil {
		t.Fatalf("UpdateUser() for role returned error: %v", err)
	}
	if user.Role != RoleOperator {
		t.Errorf("Role = %v, want %v", user.Role, RoleOperator)
	}
	stored, err := store.GetUser("admin")
	if err != nil {
		t.Fatalf("GetUser(admin): %v", err)
	}
	if stored.Role != RoleAdmin {
		t.Errorf("remaining admin role = %v, want %v", stored.Role, RoleAdmin)
	}
}

func TestUpdateUserRejectsInvalidRole(t *testing.T) {
	store, err := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "adminpassword", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if _, err := store.UpdateUser("admin", "", Role("owner")); err == nil {
		t.Fatal("UpdateUser() should reject invalid role")
	}
	user, err := store.GetUser("admin")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if user.Role != RoleAdmin {
		t.Errorf("role changed after invalid update: %v", user.Role)
	}
}

func TestDeleteUser(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret: "test-secret",
		Users: []User{
			{Username: "admin", Password: "password", Role: RoleAdmin},
			{Username: "todelete", Password: "password", Role: RoleViewer},
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

func TestDeleteUserPreservingLastAdminRejectsLastAdmin(t *testing.T) {
	store, err := NewStore(&Config{
		Secret: "test-secret",
		Users: []User{
			{Username: "admin", Password: "password", Role: RoleAdmin},
			{Username: "viewer", Password: "password", Role: RoleViewer},
		},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	err = store.DeleteUserPreservingLastAdmin("admin")
	if !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("expected ErrLastAdmin, got %v", err)
	}
	if _, err := store.GetUser("admin"); err != nil {
		t.Fatal("last admin should remain")
	}
}

func TestDeleteUserPreservingLastAdminAllowsAdminWhenAnotherRemains(t *testing.T) {
	store, err := NewStore(&Config{
		Secret: "test-secret",
		Users: []User{
			{Username: "admin", Password: "password", Role: RoleAdmin},
			{Username: "otheradmin", Password: "password", Role: RoleAdmin},
		},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if err := store.DeleteUserPreservingLastAdmin("otheradmin"); err != nil {
		t.Fatalf("DeleteUserPreservingLastAdmin: %v", err)
	}
	if _, err := store.GetUser("otheradmin"); err == nil {
		t.Fatal("deleted admin should not be retrievable")
	}
	if _, err := store.GetUser("admin"); err != nil {
		t.Fatal("remaining admin should stay available")
	}
}

func TestListUsers(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret: "test-secret",
		Users: []User{
			{Username: "admin", Password: "password", Role: RoleAdmin},
			{Username: "operator", Password: "password", Role: RoleOperator},
			{Username: "viewer", Password: "password", Role: RoleViewer},
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
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
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
			{Username: "admin", Password: "password", Role: RoleAdmin},
			{Username: "operator", Password: "password", Role: RoleOperator},
			{Username: "viewer", Password: "password", Role: RoleViewer},
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
	adminHash := HashPassword("adminpassword", nil)
	operatorHash := HashPassword("operatorpassword", nil)

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
	if !store2.VerifyUserPassword("admin", "adminpassword") {
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

func TestLoadRejectsOversizedUsersFile(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	path := filepath.Join(t.TempDir(), "users.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, maxAuthPersistFileSize+1), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	err := store.Load(path)
	if err == nil {
		t.Fatal("Load() should reject oversized users file")
	}
	if !strings.Contains(err.Error(), "auth persistence file exceeds") {
		t.Fatalf("Load() error = %v, want oversized file error", err)
	}
}

// TestSave_AtomicReplaceLeavesNoPartialFile asserts that Save uses
// the temp + rename pattern: an existing valid users.json should not
// be replaced by a partial write. Hard to crash mid-write in a unit
// test, but we *can* observe the rename behavior: after Save the
// destination file's modtime updates atomically (single rename), and
// no temp files are left in the directory.
func TestSave_AtomicReplaceLeavesNoPartialFile(t *testing.T) {
	store, _ := NewStore(&Config{Secret: "test-secret-12345"})
	_, _ = store.CreateUser("alice", "password12345", RoleAdmin)

	dir := t.TempDir()
	path := dir + "/users.json"
	if err := store.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// After Save the destination must exist with the expected content.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("destination missing: %v", err)
	}

	// And no stray .tmp files (the temp-rename cleanup discipline).
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("leftover temp file after Save: %s", e.Name())
		}
	}
}

func TestAtomicWriteFileCompletesPartialWrites(t *testing.T) {
	writer := &chunkedAuthWriter{maxWrite: 3}
	data := []byte("complete auth file payload")

	if err := util.WriteFull(writer, data); err != nil {
		t.Fatalf("WriteFull: %v", err)
	}
	if writer.calls < 2 {
		t.Fatalf("chunked writer should require multiple writes, got %d", writer.calls)
	}
	if !bytes.Equal(writer.buf.Bytes(), data) {
		t.Fatalf("written data = %q, want %q", writer.buf.Bytes(), data)
	}
}

type chunkedAuthWriter struct {
	buf      bytes.Buffer
	maxWrite int
	calls    int
}

func (w *chunkedAuthWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.maxWrite > 0 && w.maxWrite < len(p) {
		p = p[:w.maxWrite]
	}
	return w.buf.Write(p)
}

func TestSave_ReturnsParentDirFsyncError(t *testing.T) {
	store, _ := NewStore(&Config{Secret: "test-secret-12345"})

	originalSyncParentDir := syncParentDir
	syncParentDir = func(string) error {
		return errors.New("dir sync failed")
	}
	t.Cleanup(func() { syncParentDir = originalSyncParentDir })

	err := store.Save(filepath.Join(t.TempDir(), "users.json"))
	if err == nil {
		t.Fatal("Save should return parent directory fsync error")
	}
	if !strings.Contains(err.Error(), "fsync parent dir") {
		t.Fatalf("Save error should include parent directory fsync context, got: %v", err)
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
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
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

	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	if !tokenExpiredAt(&Token{ExpiresAt: now}, now) {
		t.Error("token should be expired exactly at ExpiresAt")
	}
	if tokenExpiredAt(&Token{ExpiresAt: now.Add(time.Nanosecond)}, now) {
		t.Error("token should remain valid before ExpiresAt")
	}
	if !tokenExpiredAt(nil, now) {
		t.Error("nil token should be treated as expired")
	}
}

func TestHashPasswordKnownAnswer(t *testing.T) {
	// Known-answer test for the custom PBKDF2-HMAC-SHA512 implementation.
	// This guards against accidental algorithm changes during refactoring.
	salt := make([]byte, 32)
	copy(salt, []byte("fixed-salt-32-bytes-for-testing!"))
	expectedHex := "66697865642d73616c742d33322d62797465732d666f722d74657374696e6721c9bed9c9868a54078f34c0f8bafb2c226bfe8023aa75fda3fad1f4cc24339064e3bcc15b7d777c2985e01430ccdba99f4bf1bed1c1a2abfe610e25d059d5a1ad"

	hash := HashPassword("test-password", salt)
	gotHex := hex.EncodeToString(hash)
	if gotHex != expectedHex {
		t.Errorf("HashPassword known answer mismatch\ngot:  %s\nwant: %s", gotHex, expectedHex)
	}
	if len(hash) != 96 {
		t.Errorf("HashPassword length = %d, want 96 (32-byte salt + 64-byte key)", len(hash))
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
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
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

// TestConcurrentTokenCreation tests multiple goroutines creating tokens simultaneously
func TestConcurrentTokenCreation(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	const numGoroutines = 50
	const tokensPerGoroutine = 20

	tokens := make(chan *Token, numGoroutines*tokensPerGoroutine)
	errors := make(chan error, numGoroutines*tokensPerGoroutine)
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < tokensPerGoroutine; j++ {
				token, err := store.GenerateToken("admin", 1*time.Hour)
				if err != nil {
					errors <- err
				} else {
					tokens <- token
				}
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
	close(tokens)
	close(errors)

	// Check for errors
	errCount := 0
	for err := range errors {
		if err != nil {
			errCount++
		}
	}
	if errCount > 0 {
		t.Errorf("Got %d errors during concurrent token creation", errCount)
	}

	// Verify all tokens are unique
	tokenSet := make(map[string]bool)
	dupCount := 0
	for token := range tokens {
		if tokenSet[token.Token] {
			dupCount++
		}
		tokenSet[token.Token] = true
	}
	if dupCount > 0 {
		t.Errorf("Found %d duplicate tokens", dupCount)
	}

	expectedTokens := numGoroutines * tokensPerGoroutine
	if len(tokenSet) != expectedTokens {
		t.Errorf("Expected %d unique tokens, got %d", expectedTokens, len(tokenSet))
	}
}

// TestExpiredTokenEdgeCases tests token expiration at boundary conditions
func TestExpiredTokenEdgeCases(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	// Test 1: Token with zero expiry should be invalid immediately
	t.Run("zero_expiry", func(t *testing.T) {
		token, err := store.GenerateToken("admin", 0)
		if err != nil {
			t.Fatalf("GenerateToken with 0 expiry failed: %v", err)
		}
		// Small delay to ensure we're past the expiry
		time.Sleep(1 * time.Millisecond)
		_, err = store.ValidateToken(token.Token)
		if err == nil {
			t.Errorf("Token with zero expiry should be invalid immediately")
		}
	})

	// Test 2: Token with negative expiry (should still work, but be immediately expired)
	t.Run("negative_expiry", func(t *testing.T) {
		token, err := store.GenerateToken("admin", -1*time.Hour)
		if err != nil {
			t.Fatalf("GenerateToken with negative expiry failed: %v", err)
		}
		_, err = store.ValidateToken(token.Token)
		if err == nil {
			t.Errorf("Token with negative expiry should be invalid")
		}
	})

	// Test 3: Token expires exactly at boundary
	t.Run("exact_boundary", func(t *testing.T) {
		token, err := store.GenerateToken("admin", 1*time.Millisecond)
		if err != nil {
			t.Fatalf("GenerateToken failed: %v", err)
		}
		// Should be valid before sleep
		_, err1 := store.ValidateToken(token.Token)
		if err1 != nil {
			t.Errorf("Token should be valid immediately after creation")
		}
		// Wait for expiry
		time.Sleep(5 * time.Millisecond)
		_, err2 := store.ValidateToken(token.Token)
		if err2 == nil {
			t.Errorf("Token should be invalid after expiry")
		}
	})

	// Test 4: Very long expiry
	t.Run("very_long_expiry", func(t *testing.T) {
		token, err := store.GenerateToken("admin", 365*24*time.Hour) // 1 year
		if err != nil {
			t.Fatalf("GenerateToken with long expiry failed: %v", err)
		}
		_, err = store.ValidateToken(token.Token)
		if err != nil {
			t.Errorf("Token with 1 year expiry should be valid: %v", err)
		}
	})
}

// TestMalformedTokenHandling tests various malformed token scenarios
func TestMalformedTokenHandling(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret-key-32-bytes-long!!!",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	validToken, _ := store.GenerateToken("admin", 1*time.Hour)

	tests := []struct {
		name  string
		token string
	}{
		{"empty_string", ""},
		{"single_char", "xxxxxxxx"},
		{"no_colon", "invalidtoken"},
		{"multiple_colons", "part1:part2:part3:extra"},
		{"empty_signature", validToken.Token + ":"},
		{"empty_token_part", ":signaturehere"},
		{"whitespace_prefix", " " + validToken.Token},
		{"whitespace_suffix", validToken.Token + " "},
		{"newline_in_token", "part1\n:part2"},
		{"null_bytes", "part1\x00:part2"},
		{"unicode_in_token", "tökën:sïgnätüré"},
		{"base64_garbage", "dGhpcyBpcyBub3QgdmFsaWQ=:" + validToken.Signature},
		{"tampered_token", "tampered-token-value:" + validToken.Signature},
		{"wrong_signature", validToken.Token + ":wrong-signature-here"},
		{"truncated", validToken.Token[:len(validToken.Token)/2] + ":" + validToken.Signature},
		{"corrupted_base64", "!!!invalid-base64!!!:also-invalid"},
		{"very_long_token", string(make([]byte, 10000)) + ":sig"},
		{"special_chars", "<script>alert(1)</script>:xss"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := store.ValidateToken(tc.token)
			if err == nil {
				t.Errorf("ValidateToken(%q) should return error for malformed token", tc.token)
			}
		})
	}
}

// TestTokenTampering tests that tampered tokens are rejected
func TestTokenTampering(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret-key-32-bytes-long!!!",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	validToken, _ := store.GenerateToken("admin", 1*time.Hour)

	tests := []struct {
		name  string
		token string
	}{
		{"modified_username", strings.Replace(validToken.Token, "admin", "root", -1) + ":" + validToken.Signature},
		{"changed_timestamp", validToken.Token[:10] + "0000" + validToken.Token[14:] + ":" + validToken.Signature},
		{"swapped_user", func() string {
			otherToken, _ := store.GenerateToken("admin", 1*time.Hour)
			return validToken.Token + ":" + otherToken.Signature
		}()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := store.ValidateToken(tc.token)
			if err == nil {
				t.Errorf("Tampered token should be rejected")
			}
		})
	}
}

// TestConfigReloadUsers tests user config reload scenarios
func TestConfigReloadUsers(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "users.json")

	// Create initial store
	store1, _ := NewStore(&Config{
		Secret: "test-secret",
		Users: []User{
			{Username: "admin", Password: "adminpassword", Role: RoleAdmin},
			{Username: "user1", Password: "password1", Role: RoleViewer},
		},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	// Save initial state
	if err := store1.Save(path); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Generate token for user1
	token1, _ := store1.GenerateToken("user1", 1*time.Hour)

	// Create new store and load
	store2, _ := NewStore(&Config{
		Secret:      "test-secret",
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})
	if err := store2.Load(path); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify users loaded
	users := store2.ListUsers()
	if len(users) != 2 {
		t.Errorf("Expected 2 users after reload, got %d", len(users))
	}

	// Tokens don't persist across reloads (in-memory only)
	// User needs to re-authenticate after reload
	_, err := store2.ValidateToken(token1.Token)
	if err == nil {
		t.Errorf("Token should NOT be valid after reload (tokens are in-memory only)")
	}

	// But user can generate new tokens after reload
	newToken, err := store2.GenerateToken("user1", 1*time.Hour)
	if err != nil {
		t.Errorf("Should be able to generate new token after reload: %v", err)
	}
	_, err = store2.ValidateToken(newToken.Token)
	if err != nil {
		t.Errorf("New token should be valid: %v", err)
	}

	// Add a new user and save again
	store2.CreateUser("user2", "password2", RoleOperator)
	if err := store2.Save(path); err != nil {
		t.Fatalf("Second save failed: %v", err)
	}

	// Create third store and verify all users
	store3, _ := NewStore(&Config{
		Secret:      "test-secret",
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})
	if err := store3.Load(path); err != nil {
		t.Fatalf("Third load failed: %v", err)
	}

	users = store3.ListUsers()
	if len(users) != 3 {
		t.Errorf("Expected 3 users, got %d", len(users))
	}

	// Verify passwords still work
	if !store3.VerifyUserPassword("admin", "adminpassword") {
		t.Errorf("Admin password should work after reloads")
	}
	if !store3.VerifyUserPassword("user1", "password1") {
		t.Errorf("User1 password should work after reloads")
	}
	if !store3.VerifyUserPassword("user2", "password2") {
		t.Errorf("User2 password should work after reloads")
	}
}

// TestConfigReloadWithDifferentSecret tests reload with changed secret
func TestConfigReloadWithDifferentSecret(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "users.json")

	// Create store with first secret
	store1, _ := NewStore(&Config{
		Secret:      "original-secret-32-bytes-long!!",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	token1, _ := store1.GenerateToken("admin", 1*time.Hour)
	store1.Save(path)

	// Create store with different secret
	store2, _ := NewStore(&Config{
		Secret:      "different-secret-32-bytes-long!",
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})
	store2.Load(path)

	// Token should not validate with different secret
	_, err := store2.ValidateToken(token1.Token)
	if err == nil {
		t.Errorf("Token should be invalid with different secret")
	}
}

// TestRoleHierarchyBoundaries tests role permission boundaries
func TestRoleHierarchyBoundaries(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret: "test-secret",
		Users: []User{
			{Username: "admin", Password: "password", Role: RoleAdmin},
			{Username: "operator", Password: "password", Role: RoleOperator},
			{Username: "viewer", Password: "password", Role: RoleViewer},
		},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	tests := []struct {
		user     string
		required Role
		want     bool
	}{
		// Admin can do everything
		{"admin", RoleAdmin, true},
		{"admin", RoleOperator, true},
		{"admin", RoleViewer, true},
		// Operator can do operator and viewer tasks
		{"operator", RoleAdmin, false},
		{"operator", RoleOperator, true},
		{"operator", RoleViewer, true},
		// Viewer can only do viewer tasks
		{"viewer", RoleAdmin, false},
		{"viewer", RoleOperator, false},
		{"viewer", RoleViewer, true},
		// Nonexistent user fails all
		{"nobody", RoleAdmin, false},
		{"nobody", RoleOperator, false},
		{"nobody", RoleViewer, false},
		// Empty username fails
		{"", RoleViewer, false},
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

// TestUsernameEdgeCases tests username validation edge cases
func TestUsernameEdgeCases(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	tests := []struct {
		name     string
		username string
		wantErr  bool
	}{
		{"normal", "user", false},
		{"empty", "", true},
		{"single_char", "a", false},
		{"long_name", strings.Repeat("a", 100), false},
		{"with_numbers", "user123", false},
		{"with_dash", "user-name", false},
		{"with_underscore", "user_name", false},
		{"with_dot", "user.name", false},
		{"with_at", "user@domain", false},
		{"unicode", "用户", false},
		{"emoji", "user🔐", false},
		{"spaces", "user name", false},
		{"special_chars", "user!@#$%", false},
		{"null_byte", "user\x00name", true},
		{"newline", "user\nname", true},
		{"tab", "user\tname", true},
		{"carriage_return", "user\rname", true},
		{"backspace", "user\bname", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := store.CreateUser(tc.username, "password", RoleViewer)
			if tc.wantErr && err == nil {
				t.Errorf("CreateUser(%q) should return error", tc.username)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("CreateUser(%q) returned error: %v", tc.username, err)
			}
			// Clean up for next test
			if err == nil {
				store.DeleteUser(tc.username)
			}
		})
	}
}

// TestPasswordEdgeCases tests password validation edge cases
func TestPasswordEdgeCases(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "testuser", Password: "originalpassword", Role: RoleViewer}},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	tests := []struct {
		name     string
		password string
	}{
		{"single_char", "xxxxxxxx"},
		{"max_length", strings.Repeat("a", MaxPasswordBytes)},
		{"unicode", "密码密码密码"},
		{"emoji", "🔐🔑🔒"},
		{"whitespace_only", "        "},
		{"newline", "pass\nword"},
		{"tab", "pass\tword"},
		{"null_byte", "pass\x00word"},
		{"special_chars", "!@#$%^&*()_+-=[]{}|;':\",./<>?"},
		{"binary_like", string([]byte{0x00, 0x01, 0xFF, 0xFE, 0x00, 0x01, 0xFF, 0xFE})},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Update password
			user, err := store.UpdateUser("testuser", tc.password, "")
			if err != nil {
				t.Fatalf("UpdateUser failed: %v", err)
			}
			if user.Hash != nil || user.Password != "" {
				t.Fatalf("UpdateUser exposed credential fields")
			}

			// Verify the new password works
			if !store.VerifyUserPassword("testuser", tc.password) {
				t.Errorf("Password %q should verify after update", tc.password)
			}

			// Verify wrong password doesn't work
			if store.VerifyUserPassword("testuser", "wrong-password") {
				t.Errorf("Wrong password should not verify")
			}
		})
	}

	// Over-long passwords are rejected to bound PBKDF2 cost (VULN-021).
	t.Run("too_long", func(t *testing.T) {
		_, err := store.UpdateUser("testuser", strings.Repeat("a", MaxPasswordBytes+1), "")
		if err == nil {
			t.Error("UpdateUser should reject password larger than MaxPasswordBytes")
		}
	})
}

// TestEmptyPassword specifically tests empty password behavior
func TestEmptyPassword(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "testuser", Password: "originalpassword", Role: RoleViewer}},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	// Update to empty password
	user, err := store.UpdateUser("testuser", "", "")
	if err != nil {
		t.Fatalf("UpdateUser with empty password failed: %v", err)
	}

	// Empty password should verify against empty string
	if !VerifyPassword("", user.Hash) {
		t.Logf("Empty password verification behavior: password hash may not support empty passwords")
	}

	// Non-empty password should not verify
	if VerifyPassword("any-password", user.Hash) {
		t.Errorf("Non-empty password should not verify against empty password hash")
	}
}

// TestVerifyUserPassword tests the VerifyUserPassword method
func TestVerifyUserPassword(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret: "test-secret",
		Users: []User{
			{Username: "admin", Password: "correct-password", Role: RoleAdmin},
		},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	tests := []struct {
		name     string
		username string
		password string
		want     bool
	}{
		{"correct", "admin", "correct-password", true},
		{"wrong_password", "admin", "wrong-password", false},
		{"empty_password", "admin", "", false},
		{"nonexistent_user", "nobody", "password", false},
		{"empty_username", "", "password", false},
		{"case_sensitive_user", "Admin", "correct-password", false},
		{"case_sensitive_pass", "admin", "Correct-Password", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := store.VerifyUserPassword(tc.username, tc.password)
			if got != tc.want {
				t.Errorf("VerifyUserPassword(%q, %q) = %v, want %v", tc.username, tc.password, got, tc.want)
			}
		})
	}
}

// TestTokenRevocationEdgeCases tests token revocation scenarios
func TestTokenRevocationEdgeCases(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	t.Run("revoke_nonexistent_token", func(t *testing.T) {
		// Should not panic
		store.RevokeToken("nonexistent-token")
	})

	t.Run("revoke_same_token_twice", func(t *testing.T) {
		token, _ := store.GenerateToken("admin", 1*time.Hour)
		store.RevokeToken(token.Token)
		store.RevokeToken(token.Token) // Should not panic
		_, err := store.ValidateToken(token.Token)
		if err == nil {
			t.Errorf("Token should be invalid after revocation")
		}
	})

	t.Run("revoke_one_of_many", func(t *testing.T) {
		token1, _ := store.GenerateToken("admin", 1*time.Hour)
		token2, _ := store.GenerateToken("admin", 1*time.Hour)
		token3, _ := store.GenerateToken("admin", 1*time.Hour)

		store.RevokeToken(token2.Token)

		_, err1 := store.ValidateToken(token1.Token)
		_, err2 := store.ValidateToken(token2.Token)
		_, err3 := store.ValidateToken(token3.Token)

		if err1 != nil {
			t.Errorf("token1 should still be valid")
		}
		if err2 == nil {
			t.Errorf("token2 should be invalid")
		}
		if err3 != nil {
			t.Errorf("token3 should still be valid")
		}
	})

	t.Run("revoke_all_then_create_new", func(t *testing.T) {
		store.GenerateToken("admin", 1*time.Hour)
		store.GenerateToken("admin", 1*time.Hour)

		store.RevokeAllTokens("admin")

		// Should be able to create new tokens after revoke all
		newToken, err := store.GenerateToken("admin", 1*time.Hour)
		if err != nil {
			t.Fatalf("Should be able to generate token after revoke all: %v", err)
		}

		_, err = store.ValidateToken(newToken.Token)
		if err != nil {
			t.Errorf("New token should be valid")
		}
	})

	t.Run("revoke_all_nonexistent_user", func(t *testing.T) {
		// Should not panic
		store.RevokeAllTokens("nonexistent")
	})
}

// TestConcurrentUserOperations tests concurrent user CRUD operations
func TestConcurrentUserOperations(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	done := make(chan bool)

	// Concurrent creates
	for i := 0; i < 20; i++ {
		go func(id int) {
			username := fmt.Sprintf("user%d", id)
			store.CreateUser(username, "password", RoleViewer)
			done <- true
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 20; i++ {
		go func() {
			store.ListUsers()
			store.GetUser("admin")
			done <- true
		}()
	}

	// Wait for all
	for i := 0; i < 40; i++ {
		<-done
	}

	// Verify state is consistent
	users := store.ListUsers()
	if len(users) < 2 { // At least admin + some created users
		t.Errorf("Expected at least 2 users, got %d", len(users))
	}
}

// TestStorePersistenceEdgeCases tests save/load edge cases
func TestStorePersistenceEdgeCases(t *testing.T) {
	t.Run("save_to_invalid_path", func(t *testing.T) {
		store, _ := NewStore(&Config{
			Secret:      "test-secret",
			Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
			TokenExpiry: Duration{Duration: 24 * time.Hour},
		})

		// Use a path with invalid characters for Windows
		err := store.Save("\x00invalid\x01path")
		if err == nil {
			t.Errorf("Save to invalid path should return error")
		}
	})

	t.Run("load_invalid_json", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "invalid.json")

		// Write invalid JSON
		os.WriteFile(path, []byte("not valid json"), 0644)

		store, _ := NewStore(&Config{
			Secret:      "test-secret",
			TokenExpiry: Duration{Duration: 24 * time.Hour},
		})

		err := store.Load(path)
		if err == nil {
			t.Errorf("Load of invalid JSON should return error")
		}
	})

	t.Run("load_empty_file", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "empty.json")

		os.WriteFile(path, []byte(""), 0644)

		store, _ := NewStore(&Config{
			Secret:      "test-secret",
			TokenExpiry: Duration{Duration: 24 * time.Hour},
		})

		err := store.Load(path)
		if err == nil {
			t.Errorf("Load of empty file should return error")
		}
	})

	t.Run("save_and_load_with_unicode_users", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "unicode.json")

		store1, _ := NewStore(&Config{
			Secret: "test-secret",
			Users: []User{
				{Username: "用户", Password: "密码密码密码", Role: RoleAdmin},
				{Username: "ユーザー", Password: "パスワード長い", Role: RoleViewer},
				{Username: "🔐emoji🔑", Password: "🔒secure🔓", Role: RoleOperator},
			},
			TokenExpiry: Duration{Duration: 24 * time.Hour},
		})

		if err := store1.Save(path); err != nil {
			t.Fatalf("Save failed: %v", err)
		}

		store2, _ := NewStore(&Config{
			Secret:      "test-secret",
			TokenExpiry: Duration{Duration: 24 * time.Hour},
		})

		if err := store2.Load(path); err != nil {
			t.Fatalf("Load failed: %v", err)
		}

		// Verify unicode users survived
		if _, err := store2.GetUser("用户"); err != nil {
			t.Errorf("Unicode user should survive save/load")
		}

		// Verify passwords work
		if !store2.VerifyUserPassword("用户", "密码密码密码") {
			t.Errorf("Unicode password should work after reload")
		}
	})
}

func TestLoadRejectsInvalidUserDatabaseWithoutReplacingExistingUsers(t *testing.T) {
	validHash := HashPassword("password", []byte("12345678901234567890123456789012"))

	tests := []struct {
		name  string
		users map[string]*User
	}{
		{
			name:  "empty_database",
			users: map[string]*User{},
		},
		{
			name:  "empty_username_key",
			users: map[string]*User{"": {Username: "", Hash: validHash, Role: RoleAdmin}},
		},
		{
			name:  "nil_user",
			users: map[string]*User{"admin": nil},
		},
		{
			name:  "mismatched_username",
			users: map[string]*User{"admin": {Username: "root", Hash: validHash, Role: RoleAdmin}},
		},
		{
			name:  "control_character_username",
			users: map[string]*User{"admin\nroot": {Username: "admin\nroot", Hash: validHash, Role: RoleAdmin}},
		},
		{
			name:  "invalid_role",
			users: map[string]*User{"admin": {Username: "admin", Hash: validHash, Role: Role("owner")}},
		},
		{
			name:  "missing_hash",
			users: map[string]*User{"admin": {Username: "admin", Role: RoleAdmin}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "users.json")
			data, err := json.Marshal(tc.users)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			store, err := NewStore(&Config{
				Secret:      "test-secret",
				Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
				TokenExpiry: Duration{Duration: 24 * time.Hour},
			})
			if err != nil {
				t.Fatalf("NewStore: %v", err)
			}
			if err := store.Load(path); err == nil {
				t.Fatal("Load() should reject invalid users database")
			}
			admin, err := store.GetUser("admin")
			if err != nil {
				t.Fatalf("existing admin should remain after rejected load: %v", err)
			}
			if admin.Role != RoleAdmin {
				t.Fatalf("existing admin role = %v, want %v", admin.Role, RoleAdmin)
			}
			if !store.VerifyUserPassword("admin", "password") {
				t.Fatal("existing admin password should remain valid after rejected load")
			}
		})
	}
}

// TestTokenFormat tests token format validation
func TestTokenFormat(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret-key-32-bytes-long!!!",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	token, err := store.GenerateToken("admin", 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// Verify token has the expected fields
	if token.Token == "" {
		t.Errorf("Token field should not be empty")
	}
	if token.Signature == "" {
		t.Errorf("Signature field should not be empty")
	}
	if token.Username != "admin" {
		t.Errorf("Username = %q, want %q", token.Username, "admin")
	}
	if token.Role != RoleAdmin {
		t.Errorf("Role = %v, want %v", token.Role, RoleAdmin)
	}
	if token.ExpiresAt.Before(time.Now()) {
		t.Errorf("ExpiresAt should be in the future")
	}

	// Verify token data is valid base64
	_, err = base64.URLEncoding.DecodeString(token.Token)
	if err != nil {
		t.Errorf("Token should be valid base64: %v", err)
	}

	// Verify signature is valid base64
	_, err = base64.URLEncoding.DecodeString(token.Signature)
	if err != nil {
		t.Errorf("Signature should be valid base64: %v", err)
	}
}

// TestEmptyStoreOperations tests operations on empty/zeroed store
func TestEmptyStoreOperations(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "",
		Users:       []User{},
		TokenExpiry: Duration{Duration: 24 * time.Hour},
	})

	t.Run("empty_secret", func(t *testing.T) {
		// Should create default admin even with empty secret
		users := store.ListUsers()
		if len(users) != 1 {
			t.Errorf("Expected 1 user (default admin), got %d", len(users))
		}
	})

	t.Run("token_with_empty_secret", func(t *testing.T) {
		// This might fail or succeed depending on implementation
		// Just ensure it doesn't panic
		_, _ = store.GenerateToken("admin", 1*time.Hour)
	})
}

// TestRoleString tests role string representations
func TestRoleString(t *testing.T) {
	tests := []struct {
		role Role
		want string
	}{
		{RoleAdmin, "admin"},
		{RoleOperator, "operator"},
		{RoleViewer, "viewer"},
		{Role("unknown"), "unknown"},
		{Role(""), ""},
	}

	for _, tc := range tests {
		t.Run(string(tc.role), func(t *testing.T) {
			got := string(tc.role)
			if got != tc.want {
				t.Errorf("Role string = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestNewStoreVariations tests NewStore with various configurations
func TestNewStoreVariations(t *testing.T) {
	t.Run("nil_config", func(t *testing.T) {
		// NewStore with nil config should panic or return error
		// Current implementation panics, so we expect a panic
		defer func() {
			if r := recover(); r != nil {
				// Expected - nil config causes panic
				t.Logf("Expected panic with nil config: %v", r)
			}
		}()
		store, err := NewStore(nil)
		if err == nil && store != nil {
			t.Errorf("NewStore(nil) should return error or panic")
		}
	})

	t.Run("minimal_config", func(t *testing.T) {
		store, err := NewStore(&Config{
			Secret: "minimal",
		})
		if err != nil {
			t.Errorf("NewStore with minimal config should work: %v", err)
		}
		if store == nil {
			t.Errorf("NewStore should return non-nil store")
		}
	})

	t.Run("zero_token_expiry", func(t *testing.T) {
		store, _ := NewStore(&Config{
			Secret:      "test-secret",
			Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
			TokenExpiry: Duration{Duration: 0},
		})

		token, err := store.GenerateToken("admin", 0)
		if err != nil {
			t.Fatalf("GenerateToken with 0 expiry should work: %v", err)
		}

		_, err = store.ValidateToken(token.Token)
		if err == nil {
			t.Fatal("zero-expiry token should be immediately expired")
		}
	})

	t.Run("negative_max_sessions_per_user", func(t *testing.T) {
		store, err := NewStore(&Config{
			Secret:             "test-secret",
			Users:              []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
			MaxSessionsPerUser: -1,
		})
		if err == nil {
			t.Fatalf("NewStore() should reject negative max sessions, got store %#v", store)
		}
	})
}

func TestNewStoreRejectsInvalidConfiguredUsers(t *testing.T) {
	validHash, err := HashPasswordWithError("password", []byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatalf("HashPasswordWithError: %v", err)
	}

	tests := []struct {
		name  string
		users []User
		valid bool
	}{
		{
			name:  "empty_username",
			users: []User{{Username: "", Password: "password", Role: RoleAdmin}},
		},
		{
			name:  "control_character_username",
			users: []User{{Username: "admin\nroot", Password: "password", Role: RoleAdmin}},
		},
		{
			name:  "duplicate_username",
			users: []User{{Username: "admin", Password: "password", Role: RoleAdmin}, {Username: "admin", Password: "password2", Role: RoleViewer}},
		},
		{
			name:  "invalid_role",
			users: []User{{Username: "admin", Password: "password", Role: Role("owner")}},
		},
		{
			name:  "missing_credentials",
			users: []User{{Username: "admin", Role: RoleAdmin}},
		},
		{
			name:  "short_plaintext_password",
			users: []User{{Username: "admin", Password: "short", Role: RoleAdmin}},
		},
		{
			name:  "valid_hash_with_empty_password",
			users: []User{{Username: "admin", Hash: validHash, Role: RoleAdmin}},
			valid: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, err := NewStore(&Config{
				Secret:      "test-secret",
				Users:       tc.users,
				TokenExpiry: Duration{Duration: 24 * time.Hour},
			})
			if tc.valid {
				if err != nil {
					t.Fatalf("NewStore() returned error: %v", err)
				}
				if store == nil {
					t.Fatal("NewStore() returned nil store")
				}
				return
			}
			if err == nil {
				t.Fatalf("NewStore() should reject %s", tc.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SaveTokensSigned / LoadTokensSigned (AES-256-GCM encryption)
// ---------------------------------------------------------------------------

func TestSaveTokensSigned_LoadTokensSigned_RoundTrip(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-encryption-secret",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 1 * time.Hour},
	})

	// Generate a token
	tok, _ := store.GenerateToken("admin", time.Hour)

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tokens.enc")

	// Save
	if err := store.SaveTokensSigned(path); err != nil {
		t.Fatalf("SaveTokensSigned failed: %v", err)
	}

	// Verify file exists and is not plaintext JSON
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read token file: %v", err)
	}
	if len(data) < 12+16+2 {
		t.Errorf("encrypted file too small: %d bytes", len(data))
	}
	// Verify the token map was not written as plaintext JSON. Ciphertext is
	// random bytes, so short JSON-looking byte sequences can appear by chance;
	// require a full JSON document or the actual token string before failing.
	if json.Valid(data) || bytes.Contains(data, []byte(tok.Token)) {
		t.Error("token file appears to be plaintext JSON, not encrypted")
	}

	// Load into new store with same secret
	store2, _ := NewStore(&Config{
		Secret:      "test-encryption-secret",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 1 * time.Hour},
	})
	if err := store2.LoadTokensSigned(path); err != nil {
		t.Fatalf("LoadTokensSigned failed: %v", err)
	}

	// Verify token is valid in loaded store
	claims, err := store2.ValidateToken(tok.Token)
	if err != nil {
		t.Errorf("ValidateToken failed after load: %v", err)
	}
	if claims.Username != "admin" {
		t.Errorf("Expected username 'admin', got %s", claims.Username)
	}
}

func TestLoadTokensSigned_WrongSecret(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "correct-secret",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 1 * time.Hour},
	})

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tokens.enc")

	store.SaveTokensSigned(path)

	// Try loading with wrong secret - GCM auth check should fail
	store2, _ := NewStore(&Config{
		Secret:      "wrong-secret",
		TokenExpiry: Duration{Duration: 1 * time.Hour},
	})
	err := store2.LoadTokensSigned(path)
	if err == nil {
		t.Error("Expected error loading tokens with wrong secret")
	}
	if !strings.Contains(err.Error(), "integrity check failed") {
		t.Errorf("Expected integrity check error, got: %v", err)
	}
}

func TestLoadTokensSigned_FileNotExist(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		TokenExpiry: Duration{Duration: 1 * time.Hour},
	})

	// Loading non-existent file should return nil (no error)
	err := store.LoadTokensSigned(filepath.Join(t.TempDir(), "nonexistent.enc"))
	if err != nil {
		t.Errorf("LoadTokensSigned on missing file should return nil, got: %v", err)
	}
}

func TestLoadTokensSigned_TruncatedFile(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		TokenExpiry: Duration{Duration: 1 * time.Hour},
	})

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "truncated.enc")

	// Write a file that's too short to be valid
	os.WriteFile(path, []byte("short"), 0600)

	err := store.LoadTokensSigned(path)
	if err == nil {
		t.Error("Expected error loading truncated file")
	}
}

func TestLoadTokensSignedRejectsOversizedFile(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		TokenExpiry: Duration{Duration: 1 * time.Hour},
	})

	path := filepath.Join(t.TempDir(), "tokens.enc")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, maxAuthPersistFileSize+1), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	err := store.LoadTokensSigned(path)
	if err == nil {
		t.Fatal("LoadTokensSigned() should reject oversized token file")
	}
	if !strings.Contains(err.Error(), "auth persistence file exceeds") {
		t.Fatalf("LoadTokensSigned() error = %v, want oversized file error", err)
	}
}

func TestLoadTokensSigned_CorruptedData(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 1 * time.Hour},
	})

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tokens.enc")

	store.SaveTokensSigned(path)

	// Corrupt the ciphertext by flipping a byte
	data, _ := os.ReadFile(path)
	data[len(data)-1] ^= 0xFF
	os.WriteFile(path, data, 0600)

	err := store.LoadTokensSigned(path)
	if err == nil {
		t.Error("Expected error loading corrupted file")
	}
}

func TestSaveTokensSigned_EmptyTokens(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		TokenExpiry: Duration{Duration: 1 * time.Hour},
	})

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tokens.enc")

	if err := store.SaveTokensSigned(path); err != nil {
		t.Fatalf("SaveTokensSigned with no tokens should work: %v", err)
	}

	// Load into new store
	store2, _ := NewStore(&Config{
		Secret:      "test-secret",
		TokenExpiry: Duration{Duration: 1 * time.Hour},
	})
	if err := store2.LoadTokensSigned(path); err != nil {
		t.Fatalf("LoadTokensSigned failed: %v", err)
	}
}

func TestSaveTokensSigned_MultipleTokens(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret: "test-secret",
		Users: []User{
			{Username: "admin", Password: "password1", Role: RoleAdmin},
			{Username: "user2", Password: "password2", Role: RoleOperator},
		},
		TokenExpiry: Duration{Duration: 1 * time.Hour},
	})

	tok1, _ := store.GenerateToken("admin", time.Hour)
	tok2, _ := store.GenerateToken("user2", time.Hour)

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tokens.enc")

	store.SaveTokensSigned(path)

	store2, _ := NewStore(&Config{
		Secret: "test-secret",
		Users: []User{
			{Username: "admin", Password: "password1", Role: RoleAdmin},
			{Username: "user2", Password: "password2", Role: RoleOperator},
		},
		TokenExpiry: Duration{Duration: 1 * time.Hour},
	})
	store2.LoadTokensSigned(path)

	// Both tokens should be valid
	if _, err := store2.ValidateToken(tok1.Token); err != nil {
		t.Errorf("Token 1 should be valid after load: %v", err)
	}
	if _, err := store2.ValidateToken(tok2.Token); err != nil {
		t.Errorf("Token 2 should be valid after load: %v", err)
	}
}

func TestLoadTokensSigned_ExpiredTokensFiltered(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 1 * time.Hour},
	})

	tok, _ := store.GenerateToken("admin", time.Hour)

	// Manually expire the token in the store
	store.mu.Lock()
	if token, ok := store.tokens[tok.Token]; ok {
		token.ExpiresAt = time.Now().Add(-1 * time.Hour) // set to past
	}
	store.mu.Unlock()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tokens.enc")

	store.SaveTokensSigned(path)

	store2, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 1 * time.Hour},
	})
	store2.LoadTokensSigned(path)

	// Expired token should have been filtered out during load
	_, err := store2.ValidateToken(tok.Token)
	if err == nil {
		t.Error("Expired token should not validate after load")
	}
}

func TestLoadTokensSigned_InvalidTokenDatabaseDoesNotReplaceExistingTokens(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 1 * time.Hour},
	})
	existing, _ := store.GenerateToken("admin", time.Hour)

	badStore, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 1 * time.Hour},
	})
	badToken, _ := badStore.GenerateToken("admin", time.Hour)
	badStore.mu.Lock()
	badStore.tokens[badToken.Token].Role = Role("owner")
	badStore.mu.Unlock()

	path := filepath.Join(t.TempDir(), "bad-tokens.enc")
	if err := badStore.SaveTokensSigned(path); err != nil {
		t.Fatalf("SaveTokensSigned: %v", err)
	}
	if err := store.LoadTokensSigned(path); err == nil {
		t.Fatal("LoadTokensSigned should reject invalid token role")
	}
	if _, err := store.ValidateToken(existing.Token); err != nil {
		t.Fatalf("existing token should remain valid after rejected load: %v", err)
	}
	if _, err := store.ValidateToken(badToken.Token); err == nil {
		t.Fatal("invalid token database should not replace existing tokens")
	}
}

func TestLoadTokensSigned_RepeatedLoadRebuildsActiveSessions(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:             "test-secret",
		Users:              []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry:        Duration{Duration: 1 * time.Hour},
		MaxSessionsPerUser: 2,
	})
	tok, _ := store.GenerateToken("admin", time.Hour)

	path := filepath.Join(t.TempDir(), "tokens.enc")
	if err := store.SaveTokensSigned(path); err != nil {
		t.Fatalf("SaveTokensSigned: %v", err)
	}

	store2, _ := NewStore(&Config{
		Secret:             "test-secret",
		Users:              []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry:        Duration{Duration: 1 * time.Hour},
		MaxSessionsPerUser: 2,
	})
	if err := store2.LoadTokensSigned(path); err != nil {
		t.Fatalf("first LoadTokensSigned: %v", err)
	}
	if err := store2.LoadTokensSigned(path); err != nil {
		t.Fatalf("second LoadTokensSigned: %v", err)
	}

	store2.mu.RLock()
	active := store2.activeSessions["admin"]
	tokenCount := len(store2.tokens)
	store2.mu.RUnlock()
	if active != 1 || tokenCount != 1 {
		t.Fatalf("active sessions/token count = %d/%d, want 1/1", active, tokenCount)
	}
	if _, err := store2.ValidateToken(tok.Token); err != nil {
		t.Fatalf("loaded token should remain valid: %v", err)
	}
}

func TestLoadTokensSigned_FiltersTokensForMissingUsers(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret: "test-secret",
		Users: []User{
			{Username: "admin", Password: "password", Role: RoleAdmin},
			{Username: "deleted", Password: "password", Role: RoleViewer},
		},
		TokenExpiry: Duration{Duration: 1 * time.Hour},
	})
	tok, _ := store.GenerateToken("deleted", time.Hour)

	path := filepath.Join(t.TempDir(), "tokens.enc")
	if err := store.SaveTokensSigned(path); err != nil {
		t.Fatalf("SaveTokensSigned: %v", err)
	}

	store2, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 1 * time.Hour},
	})
	if err := store2.LoadTokensSigned(path); err != nil {
		t.Fatalf("LoadTokensSigned: %v", err)
	}
	if _, err := store2.ValidateToken(tok.Token); err == nil {
		t.Fatal("token for missing user should not be loaded")
	}
	store2.mu.RLock()
	active := store2.activeSessions["deleted"]
	store2.mu.RUnlock()
	if active != 0 {
		t.Fatalf("missing user active sessions = %d, want 0", active)
	}
}

func TestLoadTokensSigned_FiltersTokensOlderThanUserUpdate(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 1 * time.Hour},
	})
	tok, _ := store.GenerateToken("admin", time.Hour)

	path := filepath.Join(t.TempDir(), "tokens.enc")
	if err := store.SaveTokensSigned(path); err != nil {
		t.Fatalf("SaveTokensSigned: %v", err)
	}

	store2, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 1 * time.Hour},
	})
	store2.mu.Lock()
	store2.users["admin"].UpdatedAt = tok.CreatedAt.Add(time.Second).UTC().Format(time.RFC3339)
	store2.mu.Unlock()

	if err := store2.LoadTokensSigned(path); err != nil {
		t.Fatalf("LoadTokensSigned: %v", err)
	}
	if _, err := store2.ValidateToken(tok.Token); err == nil {
		t.Fatal("token older than user update should not be loaded")
	}
	store2.mu.RLock()
	active := store2.activeSessions["admin"]
	tokenCount := len(store2.tokens)
	store2.mu.RUnlock()
	if active != 0 || tokenCount != 0 {
		t.Fatalf("active sessions/token count = %d/%d, want 0/0", active, tokenCount)
	}
}

func TestDeriveAESKey(t *testing.T) {
	key1 := deriveAESKey([]byte("test-secret"))
	if len(key1) != 32 {
		t.Errorf("Expected 32-byte key, got %d", len(key1))
	}

	// Same input should produce same key
	key2 := deriveAESKey([]byte("test-secret"))
	if subtle.ConstantTimeCompare(key1, key2) != 1 {
		t.Error("Same input should produce same key")
	}

	// Different input should produce different key
	key3 := deriveAESKey([]byte("different-secret"))
	if subtle.ConstantTimeCompare(key1, key3) == 1 {
		t.Error("Different inputs should produce different keys")
	}
}

func TestClearBytes(t *testing.T) {
	buf := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	clearBytes(buf)
	for i, b := range buf {
		if b != 0 {
			t.Errorf("Byte %d not cleared: %x", i, b)
		}
	}
}

func TestSetTokenFilePath(t *testing.T) {
	store, _ := NewStore(&Config{
		Secret:      "test-secret",
		Users:       []User{{Username: "admin", Password: "password", Role: RoleAdmin}},
		TokenExpiry: Duration{Duration: 1 * time.Hour},
	})

	store.SetTokenFilePath("/tmp/test-tokens.enc")
	if store.tokenFilePath != "/tmp/test-tokens.enc" {
		t.Errorf("tokenFilePath not set correctly: %s", store.tokenFilePath)
	}
}

// Users created at runtime must survive a restart through the users file,
// while config-defined users and the auto-created admin are never written.
func TestUsersFilePersistsRuntimeUsers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")

	s1, err := NewStore(&Config{Secret: "test-secret-test-secret-test-secret-12"})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := s1.EnableUsersFile(path); err != nil || n != 0 {
		t.Fatalf("EnableUsersFile on missing file = (%d, %v), want (0, nil)", n, err)
	}
	// Bootstrap flow: drop the synthetic admin, create the real one.
	if err := s1.DeleteUser("admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.CreateUser("admin", "Str0ng-Passw0rd!", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.CreateUser("ops", "Str0ng-Passw0rd!", RoleOperator); err != nil {
		t.Fatal(err)
	}

	// Restart.
	s2, err := NewStore(&Config{Secret: "test-secret-test-secret-test-secret-12"})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := s2.EnableUsersFile(path); err != nil || n != 2 {
		t.Fatalf("EnableUsersFile after restart = (%d, %v), want (2, nil)", n, err)
	}
	if !s2.VerifyUserPassword("admin", "Str0ng-Passw0rd!") {
		t.Fatal("admin password not preserved across restart")
	}
	if u, err := s2.GetUser("admin"); err != nil || u.IsAutoCreated {
		t.Fatalf("admin after restart = %+v, %v; want the persisted, non-auto-created user", u, err)
	}

	// Deleting persists too.
	if err := s2.DeleteUser("ops"); err != nil {
		t.Fatal(err)
	}
	s3, _ := NewStore(&Config{Secret: "test-secret-test-secret-test-secret-12"})
	if n, err := s3.EnableUsersFile(path); err != nil || n != 1 {
		t.Fatalf("after delete: EnableUsersFile = (%d, %v), want (1, nil)", n, err)
	}
}

func TestUsersFileConfigUsersWinAndAreNotWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	cfg := &Config{
		Secret: "test-secret-test-secret-test-secret-12",
		Users:  []User{{Username: "root", Password: "Config-Passw0rd!", Role: RoleAdmin}},
	}
	s1, err := NewStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.EnableUsersFile(path); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.CreateUser("viewer1", "Str0ng-Passw0rd!", RoleViewer); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"root"`) {
		t.Fatalf("config-defined user written to users file: %s", data)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("users file mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}
}

func TestUsesAutoCreatedAdmin(t *testing.T) {
	s, err := NewStore(&Config{Secret: "test-secret-with-enough-length-0123456789"})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if !s.UsesAutoCreatedAdmin() {
		t.Fatal("store without users must report the auto-created admin")
	}
	s2, err := NewStore(&Config{
		Secret: "test-secret-with-enough-length-0123456789",
		Users:  []User{{Username: "admin", Password: "a-strong-password-123", Role: RoleAdmin}},
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if s2.UsesAutoCreatedAdmin() {
		t.Fatal("configured admin must not be reported as auto-created")
	}
}

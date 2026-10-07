package auth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func configUsersTestStore(t *testing.T, usersFile string) *Store {
	t.Helper()
	s, err := NewStore(&Config{
		Secret: "test-secret-test-secret-test-secret-12",
		Users: []User{
			{Username: "root", Password: "Config-Passw0rd!", Role: RoleAdmin},
			{Username: "cfguser", Password: "Config-Passw0rd!", Role: RoleViewer},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnableUsersFile(usersFile); err != nil {
		t.Fatal(err)
	}
	return s
}

// F437: config-defined users cannot be deleted or changed at runtime; such a
// change was applied in memory and silently undone by the next restart.
func TestConfigDefinedUsersCannotBeChangedAtRuntime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s := configUsersTestStore(t, path)
	tok, err := s.GenerateToken("cfguser", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.UpdateUser("cfguser", "Api-Passw0rd-123", ""); !errors.Is(err, ErrConfigUser) {
		t.Fatalf("password change of config user = %v, want ErrConfigUser", err)
	}
	if _, err := s.UpdateUser("cfguser", "", RoleOperator); !errors.Is(err, ErrConfigUser) {
		t.Fatalf("role change of config user = %v, want ErrConfigUser", err)
	}
	if err := s.DeleteUser("cfguser"); !errors.Is(err, ErrConfigUser) {
		t.Fatalf("DeleteUser(config user) = %v, want ErrConfigUser", err)
	}
	if err := s.DeleteUserPreservingLastAdmin("cfguser"); !errors.Is(err, ErrConfigUser) {
		t.Fatalf("DeleteUserPreservingLastAdmin(config user) = %v, want ErrConfigUser", err)
	}
	if !s.VerifyUserPassword("cfguser", "Config-Passw0rd!") {
		t.Fatal("config user's password changed by a refused update")
	}
	if u, err := s.GetUser("cfguser"); err != nil || u.Role != RoleViewer || !u.ConfigDefined() {
		t.Fatalf("config user after refused changes = %+v, %v", u, err)
	}
	if _, err := s.ValidateToken(tok.Token); err != nil {
		t.Fatalf("refused change revoked the config user's session: %v", err)
	}

	// Runtime users keep working and stay consistent across a restart.
	if _, err := s.CreateUser("rt", "Runtime-Passw0rd1", RoleViewer); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateUser("rt", "Runtime-Passw0rd2", RoleOperator); err != nil {
		t.Fatal(err)
	}
	restarted := configUsersTestStore(t, path)
	if !restarted.VerifyUserPassword("rt", "Runtime-Passw0rd2") || !restarted.VerifyUserPassword("cfguser", "Config-Passw0rd!") {
		t.Fatal("restart does not match the pre-restart state")
	}
	for _, u := range restarted.ListUsers() {
		if want := u.Username != "rt"; u.ConfigDefined() != want {
			t.Errorf("ListUsers %s ConfigDefined = %v, want %v", u.Username, u.ConfigDefined(), want)
		}
	}
	if err := restarted.DeleteUser("rt"); err != nil {
		t.Fatalf("DeleteUser(runtime user) = %v", err)
	}
}

// F438: a users-file write failure is returned (ErrUsersPersist) and the
// in-memory change is rolled back, instead of being logged while memory
// diverges from what a restart restores.
func TestUsersFileWriteFailureRollsBackInMemoryChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s := configUsersTestStore(t, path)
	if _, err := s.CreateUser("keep", "Runtime-Passw0rd1", RoleViewer); err != nil {
		t.Fatal(err)
	}
	tok, err := s.GenerateToken("keep", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Inject the failure: the atomic rename onto a directory fails.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := s.CreateUser("ghost", "Runtime-Passw0rd1", RoleViewer); !errors.Is(err, ErrUsersPersist) {
		t.Fatalf("CreateUser = %v, want ErrUsersPersist", err)
	}
	if _, err := s.GetUser("ghost"); err == nil {
		t.Fatal("failed CreateUser left the user in memory")
	}
	if _, err := s.UpdateUser("keep", "Runtime-Passw0rd2", RoleOperator); !errors.Is(err, ErrUsersPersist) {
		t.Fatalf("UpdateUser = %v, want ErrUsersPersist", err)
	}
	if !s.VerifyUserPassword("keep", "Runtime-Passw0rd1") {
		t.Fatal("failed UpdateUser changed the password in memory")
	}
	if u, _ := s.GetUser("keep"); u == nil || u.Role != RoleViewer {
		t.Fatalf("failed UpdateUser changed the role in memory: %+v", u)
	}
	if err := s.DeleteUser("keep"); !errors.Is(err, ErrUsersPersist) {
		t.Fatalf("DeleteUser = %v, want ErrUsersPersist", err)
	}
	if _, err := s.GetUser("keep"); err != nil {
		t.Fatal("failed DeleteUser removed the user from memory")
	}
	if _, err := s.ValidateToken(tok.Token); err != nil {
		t.Fatalf("failed update/delete revoked the session: %v", err)
	}

	// Repair: the change now applies and a restart sees it.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateUser("keep", "Runtime-Passw0rd2", ""); err != nil {
		t.Fatal(err)
	}
	if !configUsersTestStore(t, path).VerifyUserPassword("keep", "Runtime-Passw0rd2") {
		t.Fatal("repaired update not persisted")
	}
}

// F438: replacing the auto-created admin is all-or-nothing, so a write
// failure cannot leave a store with zero users.
func TestReplaceAutoCreatedAdminIsAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s, err := NewStore(&Config{Secret: "test-secret-test-secret-test-secret-12"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnableUsersFile(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceAutoCreatedAdmin("owner", "Owner-Passw0rd1"); !errors.Is(err, ErrUsersPersist) {
		t.Fatalf("ReplaceAutoCreatedAdmin = %v, want ErrUsersPersist", err)
	}
	if !s.UsesAutoCreatedAdmin() || len(s.ListUsers()) != 1 {
		t.Fatalf("placeholder admin not restored: users=%d", len(s.ListUsers()))
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	u, err := s.ReplaceAutoCreatedAdmin("owner", "Owner-Passw0rd1")
	if err != nil || u.Role != RoleAdmin || u.IsAutoCreated {
		t.Fatalf("ReplaceAutoCreatedAdmin = %+v, %v", u, err)
	}
	if s.UsesAutoCreatedAdmin() {
		t.Fatal("placeholder still present after replacement")
	}
	if _, err := s.ReplaceAutoCreatedAdmin("again", "Owner-Passw0rd1"); err == nil {
		t.Fatal("second replacement must fail: no placeholder left")
	}
}
